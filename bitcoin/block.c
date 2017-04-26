#include "bitcoin/block.h"
#include "bitcoin/pullpush.h"
#include "bitcoin/tx.h"
#include <ccan/str/hex/hex.h>

const struct sha256_double genesis_blockhash
= { { .u.u8 = {
		0xff, 0x9f, 0x1c, 0x01, 0x16, 0xd1, 0x9d, 0xe7,
		0xc9, 0x96, 0x38, 0x45, 0xe1, 0x29, 0xf9, 0xed,
		0x1b, 0xfc, 0x0b, 0x37, 0x6e, 0xb5, 0x4f, 0xd7,
		0xaf, 0xa4, 0x2e, 0x0d, 0x41, 0x8c, 0x8b, 0xb6
		} } };


/* Encoding is <blockhdr> <varint-num-txs> <tx>... */
struct bitcoin_block *bitcoin_block_from_hex(const tal_t *ctx,
					     const char *hex, size_t hexlen)
{
	struct bitcoin_block *b;
	u8 *linear_tx;
	const u8 *p;
	size_t len, i, num;

	if (hexlen && hex[hexlen-1] == '\n')
		hexlen--;

	/* Set up the block for success. */
	b = tal(ctx, struct bitcoin_block);

	/* De-hex the array. */
	len = hex_data_size(hexlen);
	p = linear_tx = tal_arr(ctx, u8, len);
	if (!hex_decode(hex, hexlen, linear_tx, len))
		return tal_free(b);

	pull(&p, &len, &b->hdr, sizeof(b->hdr));
	num = pull_varint(&p, &len);
	b->tx = tal_arr(b, struct bitcoin_tx *, num);
	for (i = 0; i < num; i++)
		b->tx[i] = pull_bitcoin_tx(b->tx, &p, &len);

	/* We should end up not overrunning, nor have extra */
	if (!p || len)
		return tal_free(b);

	tal_free(linear_tx);
	return b;
}

bool bitcoin_blkid_from_hex(const char *hexstr, size_t hexstr_len,
			    struct sha256_double *blockid)
{
	return bitcoin_txid_from_hex(hexstr, hexstr_len, blockid);
}

bool bitcoin_blkid_to_hex(const struct sha256_double *blockid,
			  char *hexstr, size_t hexstr_len)
{
	return bitcoin_txid_to_hex(blockid, hexstr, hexstr_len);
}
