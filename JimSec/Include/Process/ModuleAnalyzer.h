#pragma once
#include "../../../../JimSec/JimSec/Include/Process/Module.h"

namespace Process
{
    class Memory;
    class ModuleAnalyzer
    {
    private:
        /**
         * @brief Controleert of een opcode een relatieve JMP-instructie is.
         *
         * Deze functie controleert of de opgegeven x86/x64 opcode overeenkomt
         * met een near relative JMP instructie (opcode 0xE9).
         *
         * @param opcode
         * Input: De eerste byte van de instructie die gecontroleerd moet worden.
         *
         * @return
         * TRUE wanneer de opcode een relatieve JMP-instructie is.
         * FALSE wanneer de opcode niet overeenkomt met een relatieve JMP.
         *
         * @note
         * Deze functie controleert alleen de opcode byte en analyseert geen
         * volledige instructie-opbouw of operanden.
         */
        static BOOLEAN IsRelativeJmp(unsigned char opcode);
        Memory& _memory;
    public:
        /**
         * @brief Initialiseert een ModuleAnalyzer object.
         *
         * Maakt een analyzer aan die gebruikmaakt van het opgegeven
         * Memory object voor geheugenoperaties.
         *
         * @param memory
         * Referentie naar het Memory object dat gebruikt wordt
         * voor het lezen en analyseren van geheugen.
         *
         * @note
         * Het Memory object wordt niet gekopieerd en wordt niet
         * door ModuleAnalyzer beheerd.
         * Het object moet geldig blijven gedurende de levensduur
         * van deze ModuleAnalyzer instantie.
         */
        explicit ModuleAnalyzer(Memory& memory);
        /**
         * @brief Haalt het geheugenadres en de grootte van een PE-sectie op.
         *
         * Deze functie berekent het virtuele adres van een specifieke sectie
         * binnen een geladen PE-image en geeft de locatie en grootte terug.
         *
         * De functie kopieert geen geheugen en alloceert geen nieuwe buffer.
         * De teruggegeven pointer verwijst rechtstreeks naar het bestaande
         * geheugen van de geladen module.
         *
         * @param sections
         * Input: Een array met IMAGE_SECTION_HEADER structuren
         *        afkomstig uit de PE-header.
         *
         * @param index
         * Input: De index van de sectie die opgehaald moet worden.
         *
         * @param base
         * Input: Het basisadres (base address) van de geladen PE-image.
         *
         * @param buffer
         * Output: Ontvangt het virtuele geheugenadres van de geselecteerde sectie.
         *
         * @param size
         * Output: Ontvangt de grootte van de sectie in bytes.
         *
         * @return
         * Geeft STATUS_SUCCESS terug wanneer de sectie succesvol is gevonden.
         *
         * Geeft een foutstatus terug wanneer één van de parameters ongeldig is.
         *
         * @note
         * De teruggegeven buffer wordt niet beheerd door deze functie.
         * De caller mag dit geheugen niet vrijgeven.
         */
        void ExtractCodeSection(_In_ PIMAGE_SECTION_HEADER sections, _In_ ULONG index, _In_ PVOID base, _Out_ PVOID* buffer, _Out_ SIZE_T* size);
        /**
         * @brief Analyseert een geheugenbuffer op relatieve JMP-instructies.
         *
         * Deze functie scant een opgegeven codebuffer byte voor byte en controleert
         * op relatieve jump-instructies (JMP rel32).
         *
         * Wanneer een JMP wordt gevonden, wordt het doeladres berekend op basis van
         * het instructieadres en de relatieve offset. Het gevonden bronadres en
         * doeladres worden vervolgens gerapporteerd.
         *
         * @param buffer
         * Input: Pointer naar het geheugenblok dat geanalyseerd moet worden.
         * De buffer moet uitvoerbare code bevatten die geldig gelezen kan worden.
         *
         * @param size
         * Input: Grootte van de buffer in bytes.
         *
         * @param baseAddress
         * Input: Basisadres waarmee de positie van elke instructie berekend wordt.
         * Dit moet overeenkomen met het beginadres van de meegegeven buffer.
         *
         * @return
         * Geeft STATUS_SUCCESS terug wanneer de scan succesvol uitgevoerd is.
         *
         * @note
         * Deze functie wijzigt de inhoud van de buffer niet.
         *
         * @note
         * Het detecteren van een JMP betekent niet automatisch dat de code
         * kwaadaardig is. Verdere validatie van het doeladres is noodzakelijk.
         */
        NTSTATUS ScanJumps(_In_ PVOID buffer, _In_ SIZE_T size, _In_ PVOID baseAddress);
        // Functie die controleert of een specifiek adres binnen een legitieme module van de game valt
        BOOLEAN IsAddressInLegitimateModule(_In_ PKPROCESS Process, _In_ ULONG64 TargetAddress);
    };
}
