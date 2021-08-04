/*
The MIT License

Copyright (c) 2012 Comfirm <http://www.comfirm.se/>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include "firm-dkim.h"

stringpair **relaxed_header_canon(dkim_context_t *context, stringpair **headers, int *headerc);
char *relaxed_body_canon(char *body);
char *relaxed_body_canon_line(char *line);	

char *rtrim_lines(char *str);
char *rtrim(char *str);
char *ltrim(char *str);
char *wrap(char *str, int len);
int rsa_read_pem(RSA **rsa, char *buff, int len);
char *base64_encode(const unsigned char *input, int length);

typedef struct dkim_context_t {
	char *domain;
	char *selector;
	char *identity;
	RSA *rsa_private;
	char *skip_list;
} dkim_context_t;

dkim_context_t *dkim_context_create(char *domain, char *selector, char *identity, char *pkey_buf, int pkey_len) {
	dkim_context_t *context = calloc(sizeof(dkim_context_t), 1);
	
	context->domain = malloc(strlen(domain) + 1);
	strcpy(context->domain, domain);
	
	context->selector = malloc(strlen(selector) + 1);
	strcpy(context->selector, selector);
	
	if (identity) {
		context->identity = malloc(strlen(identity) + 1);
		strcpy(context->identity, identity);
	}
	
	if (rsa_read_pem(&(context->rsa_private), pkey_buf, pkey_len) == -1) {
		printf (" * ERROR loading rsa key\n");
		dkim_context_free(context);
		return NULL;
	}
	
	/* see http://dkim.org/specs/rfc4871-dkimbase.html#choosing-header-fields */
	char *default_skip_list = "return-path received comments keywords bcc resent-bcc dkim-signature";
	context->skip_list = malloc(strlen(default_skip_list) + 1);
	strcpy(context->skip_list, default_skip_list);

	return context;
}

void dkim_context_free(dkim_context_t *context) {
	free(context->domain);
	free(context->selector);
	free(context->identity);
	RSA_free(context->rsa_private);
	free(context->skip_list);
	free(context);
}

/* create a DKIM-signature header value
   http://tools.ietf.org/html/rfc4871 */
char *dkim_create(dkim_context_t *context, stringpair **headers, int headerc, char *body, int v) {
	int i = 0;
	
	/* relax canonicalization for headers */
	if (v) printf (" * 'Relaxing' headers...\n");
	stringpair **new_headers = relaxed_header_canon(context, headers, &headerc);
	
	/* relax canonicalization for body */
	if (v) printf (" * 'Relaxing' body...\n");
	char *new_body = relaxed_body_canon(body);
	size_t new_body_len = strlen(new_body);

	/* signature timestamp */
	time_t ts = time(NULL);

	/* hash of the canonicalized body */
	if (v) printf (" * Hashing 'relaxed' body...\n");
	unsigned char *uhash = malloc(SHA256_DIGEST_LENGTH);
	SHA256 ((unsigned char*)new_body, new_body_len, uhash);
	
	/* base64 encode the hash */
	char *bh = base64_encode(uhash, SHA256_DIGEST_LENGTH);
	free (uhash);
	
	/* create header list */
	if (v) printf (" * Creating header list...\n");
	int header_list_len = headerc - 1;
	for (i = 0; i < headerc; ++i) {
		header_list_len += strlen(new_headers[i]->key);
	}
	
	char *header_list = calloc(header_list_len + 1, sizeof(char));
	int header_list_start = 0;
	for (i = 0; i < headerc; ++i) {
		if (header_list_start) {
			header_list_start += sprintf(header_list + header_list_start, ":");
		}
	
		header_list_start += sprintf(header_list + header_list_start, "%s", new_headers[i]->key);
	}
	
	/* create DKIM header */
	if (v) printf (" * Creating a DKIM header...\n");
	char *dkim;
	int dkim_len;
	
	if (context->identity) {
		dkim_len = asprintf(&dkim, "v=1; a=rsa-sha256; s=%s; d=%s; t=%ld; i=%s; c=relaxed/relaxed; h=%s; bh=%s; b=",
			context->selector, context->domain, ts, context->identity, header_list, bh
		);
	}
	else {
		dkim_len = asprintf(&dkim, "v=1; a=rsa-sha256; s=%s; d=%s; t=%ld; c=relaxed/relaxed; h=%s; bh=%s; b=",
			context->selector, context->domain, ts, header_list, bh
		);
	}
	
	/* free some memory */
	if (v) printf (" * Freeing some memory...\n");
	free (new_body);
	free (header_list);
	free (bh);
	
	/* add dkim header to headers */
	if (v) printf (" * Adding the dkim header to headers...\n");
	new_headers[headerc] = malloc(sizeof(stringpair));
	new_headers[headerc]->key = "dkim-signature";
	new_headers[headerc]->value = dkim;
	headerc++;
	
	/* make a string of all headers */
	if (v) printf (" * Making a string of all headers...\n");
	int header_str_len = 0;
	for (i = 0; i < headerc; ++i) {
		header_str_len += strlen(new_headers[i]->key);
		header_str_len += 1;
		header_str_len += strlen(new_headers[i]->value);
		
		if (i < headerc-1) {
			header_str_len += 2;
		}
	}
	
	char *header_str = calloc(header_str_len + 1, sizeof(char));
	int header_str_start = 0;
	
	for (i = 0; i < headerc; ++i) {
		size_t key_len = strlen(new_headers[i]->key);
		size_t value_len = strlen(new_headers[i]->value);
	
		memcpy (header_str+header_str_start, new_headers[i]->key, key_len);
		header_str_start += key_len;
		
		memcpy (header_str+header_str_start, ":", 1);
		header_str_start++;
		
		memcpy (header_str+header_str_start, new_headers[i]->value, value_len);
		header_str_start += value_len;
		
		if (i < headerc-1) {
			memcpy (header_str+header_str_start, "\r\n", 2);
			header_str_start += 2;
		}
	}
	
	/* hash the headers */
	if (v) printf (" * Hashing headers...\n");
	unsigned char *hash = malloc(SHA256_DIGEST_LENGTH);
	SHA256 ((unsigned char*)header_str, header_str_start, hash);
	
	/* sign canon headers with private key */
	if (v) printf (" * Signing the header hash with the rsa key...\n");
	unsigned char *sig = malloc(RSA_size(context->rsa_private));
	unsigned int sig_len;
	
	if (RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, sig, &sig_len, context->rsa_private) == 0) {
		printf (" * ERROR RSA_sign(): %s\n", ERR_error_string(ERR_get_error(), NULL));
		free (hash);
		free (new_headers);
		free (header_str);
		free (sig);
		return NULL;
	}
	
	free (hash);

	/* base64 encode the signature */
	if (v) printf (" * Base64 encoding the signature...\n");
	char *sig_b64 = base64_encode(sig, sig_len);
	size_t sig_b64_len = strlen(sig_b64);
	
	/* add it to the dkim header */
	if (v) printf (" * Adding the signature to the dkim header...\n");
	dkim = realloc(dkim, dkim_len + sig_b64_len + 1);
	memcpy (dkim + dkim_len, sig_b64, sig_b64_len + 1);
	dkim_len += sig_b64_len;
	
	/* format header name */
	char *formatted_dkim;
	int formatted_dkim_len = asprintf(&formatted_dkim, "DKIM-Signature: %s", dkim);
	free (dkim);
	
	/* wrap dkim header */
	if (v) printf (" * Wrapping the header...\n");
	formatted_dkim = wrap(formatted_dkim, formatted_dkim_len);
	
	/* free some more memory */
	if (v) printf (" * Freeing some more memory...\n");
	for (i = 0; i < headerc; ++i) {
		if (i < headerc-1) free (new_headers[i]->key);
		if (i < headerc-1) free (new_headers[i]->value);
		free (new_headers[i]);
	}
	free (new_headers);
	free (header_str);
	free (sig);
	free (sig_b64);
		
	/* return the dkim header value */
	if (v) printf (" * Done, returning...\n");
	return formatted_dkim;
}

/* The "relaxed" Header Canonicalization Algorithm */
stringpair **relaxed_header_canon(dkim_context_t *context, stringpair **headers, int *headerc) {
	int i = 0;
	size_t e = 0;
	
	/* Copy all headers */
	int new_headerc = *headerc;
	stringpair **new_headers = (stringpair**)malloc(sizeof(stringpair*) * (new_headerc + 1));
	   
	for (i = 0; i < new_headerc; ++i) {
		size_t key_len = strlen(headers[i]->key);
		size_t val_len = strlen(headers[i]->value);
		
		new_headers[i] = (stringpair*)malloc(sizeof(stringpair));
		new_headers[i]->key = malloc(key_len+1);
		new_headers[i]->value = malloc(val_len+1);
		
		memcpy (new_headers[i]->key, headers[i]->key, key_len+1);
		memcpy (new_headers[i]->value, headers[i]->value, val_len+1);
	}

	/* Convert all header field names (not the header field values) to
	   lowercase.  For example, convert "SUBJect: AbC" to "subject: AbC". */
	for (i = 0; i < new_headerc; ++i) {
		size_t key_len = strlen(new_headers[i]->key);

		for (e = 0; e < key_len; ++e) {
			new_headers[i]->key[e] = tolower(new_headers[i]->key[e]);
		}
	}
	
	/* Remove headers in our skip list */
	char *brk;
	char *token = strtok_r(context->skip_list, " ", &brk);
	
	while (token) {
		for (i = 0; i < new_headerc; ++i) {
			if (strcmp(token, new_headers[i]->key) == 0) {
				new_headers[i]->key[0] = '\0';
			}
		}
		
		token = strtok_r(NULL, " ", &brk);
	}
	
	/* Remove all but last instance of duplicate headers */
	for (i = 0; i < new_headerc; ++i) {
		int j;
		
		for (j = i+1; j < new_headerc; ++j) {
			if (strcmp(new_headers[i]->key, new_headers[j]->key) == 0) {
				new_headers[i]->key[0] = '\0';
				break;
			}
		}
	}
	
	/* If key length has been set to zero by either of the
	   two checks above, remove the header. */
	int j = 0;
	
	for (i = 0; i < new_headerc; ++i) {
		if (strlen(new_headers[i]->key) == 0) {
			continue;
		}
		
		new_headers[j++] = new_headers[i];
	}
	
	new_headerc = j;
	
	/* Unfold all header field continuation lines as described in
	   [RFC2822]; in particular, lines with terminators embedded in
	   continued header field values (that is, CRLF sequences followed by
	   WSP) MUST be interpreted without the CRLF.  Implementations MUST
	   NOT remove the CRLF at the end of the header field value. */
	for (i = 0; i < new_headerc; ++i) {
		size_t val_len = strlen(new_headers[i]->value);
		int new_len = 0;

		for (e = 0; e < val_len; ++e) {
			if (e < val_len + 1) {
				if (!(new_headers[i]->value[e] == '\r' && new_headers[i]->value[e+1] == '\n')) {
					new_headers[i]->value[new_len++] = new_headers[i]->value[e];
				} else {
					++e;
				}
			} else {
				new_headers[i]->value[new_len++] = new_headers[i]->value[e];
			}
		}
		
		new_headers[i]->value[new_len] = '\0';
	}
	
	/* Convert all sequences of one or more WSP characters to a single SP
	   character.  WSP characters here include those before and after a
	   line folding boundary. */
	for (i = 0; i < new_headerc; ++i) {
		size_t val_len = strlen(new_headers[i]->value);
		int new_len = 0;

		for (e = 0; e < val_len; ++e) {
			if (new_headers[i]->value[e] == '\t') {
				new_headers[i]->value[e] = ' ';
			}
		
			if (e > 0) {
				if (!(new_headers[i]->value[e-1] == ' ' && new_headers[i]->value[e] == ' ')) {
					new_headers[i]->value[new_len++] = new_headers[i]->value[e];
				} 
			} else {
				new_headers[i]->value[new_len++] = new_headers[i]->value[e];
			}
		}
		
		new_headers[i]->value[new_len] = '\0';
	}
	
	/* Delete all WSP characters at the end of each unfolded header field
		   value. */   
		/* Delete any WSP characters remaining before and after the colon
	   separating the header field name from the header field value.  The
	   colon separator MUST be retained. */
	for (i = 0; i < new_headerc; ++i) {
		new_headers[i]->value = rtrim(new_headers[i]->value);
		new_headers[i]->value = ltrim(new_headers[i]->value);
	}
	
	return new_headers;
}


/* The "relaxed" Body Canonicalization Algorithm */
char *relaxed_body_canon(char *body) {
	size_t i = 0;
	size_t offset = 0;
	size_t body_len = strlen(body);
	
	char *new_body = malloc(body_len*2+3);
	size_t new_body_len = 0;

	for (i = 0; i < body_len; ++i) {
		int is_r = 0;
	
		if (body[i] == '\n') {
			if (i > 0) {
				if (body[i-1] == '\r') {
					i--;
					is_r = 1;
				}
			}
			
			char *line = malloc(i - offset + 1);	
			memcpy (line, body+offset, i-offset);
			line[i-offset] = '\0';
		
			relaxed_body_canon_line (line);

			size_t line_len = strlen(line);
			memcpy (new_body+new_body_len, line, line_len);
			memcpy (new_body+new_body_len+line_len, "\r\n", 2);
			new_body_len += line_len+2;
			
			if (is_r) {
				i++;
			}	
			
			offset = i+1;
			free (line);
		}
	}

	if (offset < body_len) {
		char *line = malloc(i - offset + 1);	
		memcpy (line, body+offset, i-offset);
		line[i-offset] = '\0';
	
		relaxed_body_canon_line (line);
				
		size_t line_len = strlen(line);
		memcpy (new_body+new_body_len, line, line_len);
		memcpy (new_body+new_body_len+line_len, "\r\n", 2);
		new_body_len += line_len+2;
		
		free (line);
	}

	memcpy (new_body+new_body_len, "\0", 1);
	
	/* Ignores all empty lines at the end of the message body.	"Empty
		   line" is defined in Section 3.4.3. */
	new_body = rtrim_lines(new_body);
	
	/* Note that a completely empty or missing body is canonicalized as a
		   single "CRLF"; that is, the canonicalized length will be 2 octets. */
	new_body_len = strlen(new_body);
	new_body[new_body_len++] = '\r';
	new_body[new_body_len++] = '\n';
	new_body[new_body_len] = '\0';
	
	return new_body;	
}


/* The "relaxed" Body Canonicalization Algorithm, per line */
char *relaxed_body_canon_line(char *line) {
	size_t line_len = 0;
	size_t i;
	
	/* Ignores all whitespace at the end of lines.	Implementations MUST
		   NOT remove the CRLF at the end of the line. */
	rtrim (line);
	
	/* Reduces all sequences of WSP within a line to a single SP
	   character. */
	line_len = strlen(line);
	int new_len = 0;

	for (i = 0; i < line_len; ++i) {
		if (line[i] == '\t') {
			line[i] = ' ';
		}
	
		if (i > 0) {
			if (!(line[i-1] == ' ' && line[i] == ' ')) {
				line[new_len++] = line[i];
			} 
		} else {
			line[new_len++] = line[i];
		}
	}
	
	line[new_len] = '\0';
	
	return line;
}


/* rtrim function for lines */
char *rtrim_lines(char *str) {
	char *end;
	size_t len = strlen(str);

	while (*str && len) {
		end = str + len-1;
		
		if (*end == '\r' || *end == '\n') {
			*end = '\0';
		} else {
			break;
		}
		
		len = strlen(str);
	}
	
	return str;
}


/* rtrim function */
char *rtrim(char *str) {
	char *end;
	size_t len = strlen(str);

	while (*str && len) {
		end = str + len-1;
		
		if (*end == ' ' || *end == '\t') {
			*end = '\0';
		} else {
			break;
		}
		
		len = strlen(str);
	}
	
	return str;
}


/* ltrim function */
char *ltrim(char *str) {
	char *start = str;
	size_t len = strlen(str);

	while (*start && len) {		
		if (*start == ' ' || *start == '\t') {
			start++;
		} else {
			break;
		}
		
		len = strlen(start);
	}
	
	char *n = malloc(strlen(start)+1);
	memcpy (n, start, strlen(start)+1);
	free (str);
	
	return n;
}


/* very simple word wrap function for headers */
char *wrap(char *str, int len) {
	char *tmp = malloc(len*3+1);
	int tmp_len = 0;
	int i;
	int lcount = 0;
	
	for (i = 0; i < len; ++i) {
		if (str[i] == ' ' || lcount == 75) {
			tmp[tmp_len++] = str[i];
			tmp[tmp_len++] = '\r';
			tmp[tmp_len++] = '\n';
			tmp[tmp_len++] = '\t';
			lcount = 0;
		} else {
			tmp[tmp_len++] = str[i];
			++lcount;
		}
	}
	
	tmp[tmp_len] = '\0';
	free (str);
	
	return tmp;
}


/* load an RSA key in PEM format from buff */
int rsa_read_pem(RSA **rsa, char *buff, int len) { 
	BIO *mem; 

	if ((mem = BIO_new_mem_buf(buff, len)) == NULL) { 
		goto err; 
	} 

	*rsa = PEM_read_bio_RSAPrivateKey(mem, NULL, NULL, NULL); 
	BIO_free (mem); 

	if (*rsa == NULL) { 
		goto err; 
	} 

	return 0; 

err: 
	return -1; 
} 


/* Base64 encode algorithm using openssl */
char *base64_encode(const unsigned char *input, int length) {
	BIO *bmem, *b64;
	BUF_MEM *bptr;

	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	
	BIO_write (b64, input, length);
	BIO_flush (b64);
	BIO_get_mem_ptr (b64, &bptr);

	char *buff = malloc(bptr->length);
	memcpy (buff, bptr->data, bptr->length-1);
	buff[bptr->length-1] = '\0';

	BIO_free_all (b64);

	/* remove line breaks */
	size_t buff_len = strlen(buff);
	size_t i, cur = 0;
	for (i = 0; i < buff_len; ++i) {
		if (buff[i] != '\r' && buff[i] != '\n') {
			buff[cur++] = buff[i];
		}
	}
	buff[cur] = '\0';	

	return buff;
}
