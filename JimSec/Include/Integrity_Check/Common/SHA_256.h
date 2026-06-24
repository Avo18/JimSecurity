#pragma once
#include <ntddk.h>
#include "../../../../JimSec/Include/Integrity_Check/Types/SHA256_CTX.h"


// Zorgt ervoor dat C++ de namen niet 'mangled'
//#ifdef __cplusplus
//extern "C" {
//#endif

    namespace Common
    {
        class SHA_256
        {
        private:
            SHA256_CTX* _context;
        public:
            SHA_256();
            // Functie prototypes
            void Init(SHA256_CTX* ctx);
            void Transform(SHA256_CTX* ctx, const UCHAR data[]);
            void Update(SHA256_CTX* ctx, const UCHAR data[], SIZE_T len);
            void Final(SHA256_CTX* ctx, UCHAR hash[]);
        };
    };

//#ifdef __cplusplus
//}
//#endif