#pragma once
namespace Enum
{
    enum class Section
    {
        MachineCode,
    };

    static constexpr const char* ToString[] =
    {
        ".txt",
    };

    constexpr const char* GetMessage(Section section)
    {
        return ToString[(int)section];
    }
}