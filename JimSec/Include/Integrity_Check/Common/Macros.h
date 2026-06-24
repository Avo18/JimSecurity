/*
* De volgende macro's zijn bitmanipulatie functies die worden gebruikt in het SHA-256 algoritme.
* Ze voeren rotaties en logische operaties uit op 32-bits woorden, wat essentieel is voor de complexiteit en veiligheid van de hashfunctie.
* ROTRIGHT voert een bitrotatie naar rechts uit, waarbij de bits die aan de rechterkant verdwijnen, aan de linkerkant weer verschijnen. Dit helpt bij het mengen van de bits in het algoritme.
* CH (choose) selecteert bits uit twee woorden op basis van de bits van een derde woord, wat bijdraagt aan de niet-lineariteit van het algoritme.
* MAJ (majority) kiest de meerderheid van de bits uit drie woorden, wat ook bijdraagt aan de complexiteit van de hashfunctie.
* EP0 en EP1 zijn expansiefuncties die meerdere rotaties en XOR-operaties combineren om de bits verder te mengen.
* SIG0 en SIG1 zijn kleine sigma-functies die ook rotaties en verschuivingen combineren om de bits te transformeren.
* Deze macro's zijn essentieel voor de werking van het SHA-256 algoritme, omdat ze helpen bij het creëren van een complexe en veilige hashfunctie die bestand is tegen aanvallen zoals pre-image resistance en avalanche effect.
*/
#define ROTRIGHT(word,bits) (((word) >> (bits)) | ((word) << (32-(bits))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))