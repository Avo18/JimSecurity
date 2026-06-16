#include "SecurityDriver.h"

class Authentication
{
public:
    void GenerateChallenge(unsigned char* buffer)
    {
        LARGE_INTEGER time;
        KeQuerySystemTime(&time);

        RtlCopyMemory(
            buffer,
            &time,
            sizeof(time)
        );
    }
};