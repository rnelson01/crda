 #!/usr/bin/env python
 
import io
import sys
try:
    from Cryptodome.PublicKey import RSA
except ImportError as e:
    sys.stderr.write('ERROR: Failed to import the "Cryptodome.PublicKey" module: %s\n' % e.message)
    sys.stderr.write('Please install the "pycryptodomex" Python module.\n')
    sys.stderr.write('Run 'pip install pycryptodomex' as ${USER} \n')
    sys.exit(1)


def bitwise_collect(value, radix_bits):
    words = []
    radix_mask = (1 << radix_bits) - 1
    while value != 0:
        words.append(value & radix_mask)
        value >>= radix_bits
    return words
 
def print_ssl_64(output, name, val):
    # OpenSSL expects 64-bit words given least-significant-word first.
    vwords = bitwise_collect(val, 64)

    output.write(u'static BN_ULONG {}[] = {{\n'.format(name))
    idx = 0
    for vword in vwords:
         if not idx:
            output.write(u'\t')
         output.write(u'0x{:016x}ULL, '.format(vword))
    idx += 1
    if idx == 2:
            idx = 0
            output.write(u'\n')
    if idx:
        output.write(u'\n')
    output.write(u'};\n\n')
 
def print_ssl_32(output, name, val):
    # OpenSSL expects 32-bit words given least-significant-word first.
    vwords = bitwise_collect(val, 32)

    output.write(u'static BN_ULONG {}[] = {{\n'.format(name))
    idx = 0
    for vword in vwords:
        if not idx:
            output.write(u'\t')
        output.write(u'0x{:08x}, '.format(vword))
        idx += 1
        if idx == 4:
            idx = 0
            output.write(u'\n')
    if idx:
        output.write(u'\n')
    output.write(u'};\n\n')
 
def print_ssl(output, name, val):

    output.write(u'#include <stdint.h>\n')
    output.write(u'#include <openssl/bn.h>\n')

    import struct
    if len(struct.pack('@L', 0)) == 8:
        return print_ssl_64(output, name, val)
    else:
        return print_ssl_32(output, name, val)
 
def print_ssl_keys(output, n):
    output.write(u'''
 struct pubkey {
 	struct bignum_st e, n;
 };
 
#define KEY(data) {                          \\
	.d = data,                           \\
	.top = sizeof(data)/sizeof(data[0]), \\
 }
 
#define KEYS(e,n)    { KEY(e), KEY(n), }
 
 static struct pubkey keys[] = {
 ''')
    for n in xrange(n + 1):
        output.write(u'	KEYS(e_{0}, n_{0}),\n'.format(n))
    output.write(u'};\n')
    pass
 
def print_gcrypt(output, name, val):
    # gcrypt expects 8-bit words most-significant-word first
    vwords = bitwise_collect(val, 8)
    vwords.reverse()

    output.write(u'#include <stdint.h>\n')
    output.write(u'static const uint8_t %s[%d] = {\n' % (name, len(vwords)))
    idx = 0
    for vword in vwords:
         if not idx:
            output.write(u'\t')
         output.write(u'0x{:02x}, '.format(vword))
    idx += 1
    if idx == 8:
            idx = 0
            output.write(u'\n')
    if idx:
        output.write(u'\n')
    output.write(u'};\n\n')
 
def print_gcrypt_keys(output, n):
    output.write(u'''
 struct key_params {
 	const uint8_t *e, *n;
 	uint32_t len_e, len_n;
 };
 
#define KEYS(_e, _n) {                \\
	.e = _e, .len_e = sizeof(_e), \\
	.n = _n, .len_n = sizeof(_n), \\
 }
 
 static const struct key_params __attribute__ ((unused)) keys[] = {
 ''')

    for n in range(n + 1):
        output.write(u'	KEYS(e_{0}, n_{0}),\n'.format(n))
    output.write(u'};\n')

 
modes = {
     '--ssl': (print_ssl, print_ssl_keys),
    '--gcrypt': (print_gcrypt, print_gcrypt_keys),
}

try:
    mode = sys.argv[1]
    files = sys.argv[2:-1]
    outfile = sys.argv[-1]
except IndexError:
    mode = None

if not mode in modes:
    print('Usage: {} [{}] input-file... output-file'.format(sys.argv[0], '|'.join(modes.keys())))
    sys.exit(2)
 
output = io.open(outfile, 'w')
 
 # load key
idx = 0
for f in files:
    key_contents = io.open(f, 'rb').read()
    key = RSA.importKey(key_contents)

    modes[mode][0](output, 'e_{}'.format(idx), key.e)
    modes[mode][0](output, 'n_{}'.format(idx), key.n)

    idx += 1
 
modes[mode][1](output, idx - 1)
