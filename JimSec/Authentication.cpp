#include "SecurityDriver.h"

class Authentication
{
private:
	// Hier kun je private leden en methoden toevoegen die alleen binnen de Authentication klasse toegankelijk zijn.
public:
    void GenerateChallenge(unsigned char* buffer)
    {
        LARGE_INTEGER time;
        KeQuerySystemTime(&time);

        RtlCopyMemory(buffer, &time, sizeof(time));
    }
};