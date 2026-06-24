#include <ntddk.h>
#include "../../../../JimSec/Include/Integrity_Check/Common/SHA_256.h"
#include "../../../../JimSec/Include/Integrity_Check/Common/Macros.h"
#include "../../../../JimSec/Include/Integrity_Check/Types/SHA256_CTX.h"

/*
* De constante array k bevat de eerste 32 bits van de fractionele delen van de kubuswortels van de eerste 64 priemgetallen.
* Deze waarden worden gebruikt in de SHA-256 algoritme om de hashwaarden te mengen en te versterken, 
* waardoor het moeilijker wordt om de oorspronkelijke data te achterhalen uit de hash (pre-image resistance) en dat kleine veranderingen in de input leiden tot grote veranderingen in de output (avalanche effect).
* De waarden zijn zorgvuldig gekozen om een goede verspreiding van de hashwaarden te garanderen en om de veiligheid van het algoritme te verbeteren.
* De constante array k is een essentieel onderdeel van de SHA-256 algoritme en wordt gebruikt in de transform functie om de hashwaarden bij te werken tijdens de verwerking van elk blok van data.
*/
static const ULONG k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};


Common::SHA_256::SHA_256()
{
}

/*
* De transform functie is het hart van de SHA-256 algoritme. Het neemt een blok van 512 bits (64 bytes) en verwerkt het om de hashwaarden bij te werken.
* Het blok wordt eerst uitgebreid van 16 woorden (32 bits elk) naar 64 woorden, waarbij de extra woorden worden berekend op basis van de eerdere woorden met behulp van de SIG0 en SIG1 functies.
* Vervolgens worden de hashwaarden (a, b, c, d, e, f, g, h) bijgewerkt in 64 rondes, waarbij elke ronde gebruik maakt van de functies EP0, EP1, CH en MAJ, evenals de constante k[i] en het woord m[i].
* Na alle rondes worden de hashwaarden terug opgeteld bij de oorspronkelijke waarden in de context, waardoor de hashwaarden worden bijgewerkt voor het volgende blok dat verwerkt wordt.
* Deze functie wordt telkens aangeroepen wanneer er een volledig blok van 64 bytes is verzameld in de update functie, en ook aan het einde in de final functie om de laatste gegevens te verwerken en de uiteindelijke hash te berekenen.
* De transform functie zorgt ervoor dat de hashwaarden op een complexe manier worden bijgewerkt, waardoor het moeilijk is om de oorspronkelijke data te achterhalen uit de hash (pre-image resistance) en dat kleine veranderingen in de input leiden tot grote veranderingen in de output (avalanche effect).
*/
void Common::SHA_256::Transform(SHA256_CTX* ctx, const UCHAR data[]) {
    ULONG a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    for (i = 0, j = 0; i < 16; ++i, j += 4)
		// De eerste 16 woorden van het blok worden direct uit de data gehaald en samengevoegd tot 32-bits woorden.
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    for (; i < 64; ++i)
		// De resterende 48 woorden worden berekend op basis van de eerdere woorden met behulp van de SIG0 en SIG1 functies.
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

	// De huidige hashwaarden worden opgehaald uit de context en opgeslagen in lokale variabelen.
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
		// In elke ronde worden de hashwaarden bijgewerkt met behulp van de functies EP0, EP1, CH en MAJ, evenals de constante k[i] en het woord m[i].
        t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
		// De nieuwe waarde van a wordt berekend door t1 en t2 op te tellen, waarbij t2 de uitkomst is van de MAJ functie op de huidige waarden van a, b en c.
        t2 = EP0(a) + MAJ(a, b, c);
		// De hashwaarden worden verschoven, waarbij de nieuwe waarden van a, b, c, d, e, f, g en h worden berekend op basis van de huidige waarden en de berekende t1 en t2.
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
	// Na alle rondes worden de bijgewerkte hashwaarden terug opgeteld bij de oorspronkelijke waarden in de context, waardoor de hashwaarden worden bijgewerkt voor het volgende blok dat verwerkt wordt.
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

/*
* De init functie zet de datalen en bitlen op 0, en stelt de initiële hashwaarden in volgens de SHA-256 specificatie.
* Deze waarden zijn afgeleid van de eerste 32 bits van de fractionele delen van de vierkantswortels van de eerste acht priemgetallen (2, 3, 5, 7, 11, 13, 17, 19).
* Deze initiële waarden zorgen ervoor dat de hashfunctie een goede verspreiding heeft en dat kleine veranderingen in de input leiden tot grote veranderingen in de output (avalanche effect).
* De datalen en bitlen worden gebruikt om bij te houden hoeveel data er is verwerkt, wat nodig is voor de padding in de finalisatie stap.
*/
void  Common::SHA_256::Init(SHA256_CTX* ctx) {
    ctx->datalen = 0;
    ctx->bitlen[0] = 0; ctx->bitlen[1] = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85; ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c; ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

/*
* Kan maar telkens 64 bytes verwerken, dus als er meer is, moet het in stukken worden verwerkt.
* Bijvoorbeeld, als er 100 bytes zijn, moet je eerst 64 bytes verwerken, en dan de resterende 36 bytes.
* Daarom is er een loop die door de data iterereert en telkens 64 bytes verwerkt totdat er minder dan 64 bytes over zijn.
* De bitlengte wordt ook bijgehouden, zodat we weten hoeveel data er in totaal is verwerkt, wat nodig is voor de padding in de finalisatie stap.
*/
void Common::SHA_256::Update(SHA256_CTX* ctx, const UCHAR data[], SIZE_T len) {
    SIZE_T i;
    for (i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            Common::SHA_256::Transform(ctx, ctx->data);
            ctx->bitlen[0] += 512;
            if (ctx->bitlen[0] == 0) ctx->bitlen[1]++;
            ctx->datalen = 0;
        }
    }
}

/*
* De final functie wordt aangeroepen nadat alle data is verwerkt met de update functie. 
* Het voegt padding toe aan de data zodat de totale lengte een veelvoud van 512 bits is, en voegt de totale bitlengte toe aan het einde van de data.
*/
void Common::SHA_256::Final(SHA256_CTX* ctx, UCHAR hash[]) {
    ULONG i = ctx->datalen;

    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0x00;
    }
    else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0x00;
        Common::SHA_256::Transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen[0] += ctx->datalen * 8;
    if (ctx->bitlen[0] < ctx->datalen * 8) ctx->bitlen[1]++;

    ctx->data[63] = (UCHAR)(ctx->bitlen[0]); ctx->data[62] = (UCHAR)(ctx->bitlen[0] >> 8);
    ctx->data[61] = (UCHAR)(ctx->bitlen[0] >> 16); ctx->data[60] = (UCHAR)(ctx->bitlen[0] >> 24);
    ctx->data[59] = (UCHAR)(ctx->bitlen[1]); ctx->data[58] = (UCHAR)(ctx->bitlen[1] >> 8);
    ctx->data[57] = (UCHAR)(ctx->bitlen[1] >> 16); ctx->data[56] = (UCHAR)(ctx->bitlen[1] >> 24);
    Common::SHA_256::Transform(ctx, ctx->data);

    for (i = 0; i < 4; ++i) {
		// De uiteindelijke hash wordt samengesteld door de 32-bits woorden van de state te splitsen in bytes en in het hash-array te plaatsen.
        hash[i] = (UCHAR)((ctx->state[0] >> (24 - i * 8)) & 0x000000ff);
        hash[i + 4] = (UCHAR)((ctx->state[1] >> (24 - i * 8)) & 0x000000ff);
        hash[i + 8] = (UCHAR)((ctx->state[2] >> (24 - i * 8)) & 0x000000ff);
        hash[i + 12] = (UCHAR)((ctx->state[3] >> (24 - i * 8)) & 0x000000ff);
        hash[i + 16] = (UCHAR)((ctx->state[4] >> (24 - i * 8)) & 0x000000ff);
        hash[i + 20] = (UCHAR)((ctx->state[5] >> (24 - i * 8)) & 0x000000ff);
        hash[i + 24] = (UCHAR)((ctx->state[6] >> (24 - i * 8)) & 0x000000ff);
        hash[i + 28] = (UCHAR)((ctx->state[7] >> (24 - i * 8)) & 0x000000ff);
    }
}