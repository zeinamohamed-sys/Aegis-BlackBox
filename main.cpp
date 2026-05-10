#include <algorithm>
#include <cstdint>
#include <cstring>
#include <exception>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace aegis {

#pragma pack(push, 1)
struct ImageDosHeader {
    std::uint16_t e_magic;
    std::uint8_t  e_unused[58];
    std::int32_t  e_lfanew;
};

struct ImageFileHeader {
    std::uint16_t machine;
    std::uint16_t numberOfSections;
    std::uint32_t timeDateStamp;
    std::uint32_t pointerToSymbolTable;
    std::uint32_t numberOfSymbols;
    std::uint16_t sizeOfOptionalHeader;
    std::uint16_t characteristics;
};

struct ImageDataDirectory {
    std::uint32_t virtualAddress;
    std::uint32_t size;
};

struct ImageOptionalHeader32 {
    std::uint16_t magic;
    std::uint8_t  majorLinkerVersion;
    std::uint8_t  minorLinkerVersion;
    std::uint32_t sizeOfCode;
    std::uint32_t sizeOfInitializedData;
    std::uint32_t sizeOfUninitializedData;
    std::uint32_t addressOfEntryPoint;
    std::uint32_t baseOfCode;
    std::uint32_t baseOfData;
    std::uint32_t imageBase;
    std::uint32_t sectionAlignment;
    std::uint32_t fileAlignment;
    std::uint16_t majorOperatingSystemVersion;
    std::uint16_t minorOperatingSystemVersion;
    std::uint16_t majorImageVersion;
    std::uint16_t minorImageVersion;
    std::uint16_t majorSubsystemVersion;
    std::uint16_t minorSubsystemVersion;
    std::uint32_t win32VersionValue;
    std::uint32_t sizeOfImage;
    std::uint32_t sizeOfHeaders;
    std::uint32_t checkSum;
    std::uint16_t subsystem;
    std::uint16_t dllCharacteristics;
    std::uint32_t sizeOfStackReserve;
    std::uint32_t sizeOfStackCommit;
    std::uint32_t sizeOfHeapReserve;
    std::uint32_t sizeOfHeapCommit;
    std::uint32_t loaderFlags;
    std::uint32_t numberOfRvaAndSizes;
    ImageDataDirectory dataDirectory[16];
};

struct ImageOptionalHeader64 {
    std::uint16_t magic;
    std::uint8_t  majorLinkerVersion;
    std::uint8_t  minorLinkerVersion;
    std::uint32_t sizeOfCode;
    std::uint32_t sizeOfInitializedData;
    std::uint32_t sizeOfUninitializedData;
    std::uint32_t addressOfEntryPoint;
    std::uint32_t baseOfCode;
    std::uint64_t imageBase;
    std::uint32_t sectionAlignment;
    std::uint32_t fileAlignment;
    std::uint16_t majorOperatingSystemVersion;
    std::uint16_t minorOperatingSystemVersion;
    std::uint16_t majorImageVersion;
    std::uint16_t minorImageVersion;
    std::uint16_t majorSubsystemVersion;
    std::uint16_t minorSubsystemVersion;
    std::uint32_t win32VersionValue;
    std::uint32_t sizeOfImage;
    std::uint32_t sizeOfHeaders;
    std::uint32_t checkSum;
    std::uint16_t subsystem;
    std::uint16_t dllCharacteristics;
    std::uint64_t sizeOfStackReserve;
    std::uint64_t sizeOfStackCommit;
    std::uint64_t sizeOfHeapReserve;
    std::uint64_t sizeOfHeapCommit;
    std::uint32_t loaderFlags;
    std::uint32_t numberOfRvaAndSizes;
    ImageDataDirectory dataDirectory[16];
};

struct ImageSectionHeader {
    char           name[8];
    union {
        std::uint32_t physicalAddress;
        std::uint32_t virtualSize;
    } misc;
    std::uint32_t  virtualAddress;
    std::uint32_t  sizeOfRawData;
    std::uint32_t  pointerToRawData;
    std::uint32_t  pointerToRelocations;
    std::uint32_t  pointerToLinenumbers;
    std::uint16_t  numberOfRelocations;
    std::uint16_t  numberOfLinenumbers;
    std::uint32_t  characteristics;
};

struct ImageImportDescriptor {
    std::uint32_t originalFirstThunk;
    std::uint32_t timeDateStamp;
    std::uint32_t forwarderChain;
    std::uint32_t name;
    std::uint32_t firstThunk;
};

struct ImageThunkData32 {
    std::uint32_t addressOfData;
};

struct ImageThunkData64 {
    std::uint64_t addressOfData;
};

struct ImageImportByName {
    std::uint16_t hint;
};
#pragma pack(pop)

struct SectionInfo {
    std::string name;
    std::uint32_t virtualAddress;
    std::uint32_t virtualSize;
    std::uint32_t rawSize;
    std::uint32_t rawPointer;
    std::uint32_t characteristics;
};

struct ImportEntry {
    std::string library;
    std::vector<std::string> functions;
};

struct AnalysisResult {
    std::string filePath;
    std::uint64_t fileSize = 0;
    bool isPe32Plus = false;
    std::uint16_t machine = 0;
    std::uint16_t numberOfSections = 0;
    std::uint32_t entryPoint = 0;
    std::uint64_t imageBase = 0;
    std::uint32_t sizeOfImage = 0;
    std::uint32_t sizeOfHeaders = 0;
    std::vector<SectionInfo> sections;
    std::vector<ImportEntry> imports;
};

class BinaryReader {
public:
    explicit BinaryReader(const std::string& filePath) {
        std::ifstream input(filePath, std::ios::binary);
        if (!input) {
            throw std::runtime_error("Unable to open input file: " + filePath);
        }
        input.seekg(0, std::ios::end);
        const std::streamoff size = input.tellg();
        if (size < 0) {
            throw std::runtime_error("Unable to determine file size.");
        }
        buffer_.resize(static_cast<std::size_t>(size));
        input.seekg(0, std::ios::beg);
        if (!input.read(reinterpret_cast<char*>(buffer_.data()), size)) {
            throw std::runtime_error("Failed to read file content.");
        }
    }

    template <typename T>
    T read(std::size_t offset) const {
        ensureRange(offset, sizeof(T));
        T value{};
        std::memcpy(&value, buffer_.data() + offset, sizeof(T));
        return value;
    }

    std::string readString(std::size_t offset) const {
        ensureRange(offset, 1);
        std::string value;
        for (std::size_t i = offset; i < buffer_.size() && buffer_[i] != 0; ++i) {
            value.push_back(static_cast<char>(buffer_[i]));
        }
        return value;
    }

    std::uint64_t fileSize() const {
        return static_cast<std::uint64_t>(buffer_.size());
    }

private:
    void ensureRange(std::size_t offset, std::size_t length) const {
        if (offset > buffer_.size() || length > buffer_.size() - offset) {
            throw std::out_of_range("Requested range exceeds file boundaries.");
        }
    }

    std::vector<std::uint8_t> buffer_;
};

class JsonWriter {
public:
    static std::string escape(const std::string& value) {
        std::ostringstream oss;
        for (const char ch : value) {
            switch (ch) {
                case '\\': oss << "\\\\"; break;
                case '"':  oss << "\\\""; break;
                case '\n': oss << "\\n"; break;
                case '\r': oss << "\\r"; break;
                case '\t': oss << "\\t"; break;
                default:
                    if (static_cast<unsigned char>(ch) < 0x20) {
                        oss << "\\u"
                            << std::hex << std::setw(4) << std::setfill('0')
                            << static_cast<int>(static_cast<unsigned char>(ch));
                    } else {
                        oss << ch;
                    }
                    break;
            }
        }
        return oss.str();
    }

    static void write(const AnalysisResult& result, const std::string& outputPath) {
        std::ofstream output(outputPath, std::ios::out | std::ios::trunc);
        if (!output) {
            throw std::runtime_error("Unable to open output file: " + outputPath);
        }

        output << "{\n";
        output << "  \"file_info\": {\n";
        output << "    \"file_path\": \"" << escape(result.filePath) << "\",\n";
        output << "    \"file_size\": " << result.fileSize << "\n";
        output << "  },\n";
        output << "  \"pe_headers\": {\n";
        output << "    \"format\": \"" << (result.isPe32Plus ? "PE32+" : "PE32") << "\",\n";
        output << "    \"machine\": " << result.machine << ",\n";
        output << "    \"number_of_sections\": " << result.numberOfSections << ",\n";
        output << "    \"entry_point\": " << result.entryPoint << ",\n";
        output << "    \"image_base\": " << result.imageBase << ",\n";
        output << "    \"size_of_image\": " << result.sizeOfImage << ",\n";
        output << "    \"size_of_headers\": " << result.sizeOfHeaders << "\n";
        output << "  },\n";

        output << "  \"sections\": [\n";
        for (std::size_t i = 0; i < result.sections.size(); ++i) {
            const auto& section = result.sections[i];
            output << "    {\n";
            output << "      \"name\": \"" << escape(section.name) << "\",\n";
            output << "      \"virtual_address\": " << section.virtualAddress << ",\n";
            output << "      \"virtual_size\": " << section.virtualSize << ",\n";
            output << "      \"raw_size\": " << section.rawSize << ",\n";
            output << "      \"raw_pointer\": " << section.rawPointer << ",\n";
            output << "      \"characteristics\": " << section.characteristics << "\n";
            output << "    }" << (i + 1 == result.sections.size() ? "" : ",") << "\n";
        }
        output << "  ],\n";

        output << "  \"imports\": [\n";
        for (std::size_t i = 0; i < result.imports.size(); ++i) {
            const auto& importEntry = result.imports[i];
            output << "    {\n";
            output << "      \"library\": \"" << escape(importEntry.library) << "\",\n";
            output << "      \"functions\": [";
            for (std::size_t j = 0; j < importEntry.functions.size(); ++j) {
                output << "\"" << escape(importEntry.functions[j]) << "\"";
                if (j + 1 != importEntry.functions.size()) {
                    output << ", ";
                }
            }
            output << "]\n";
            output << "    }" << (i + 1 == result.imports.size() ? "" : ",") << "\n";
        }
        output << "  ]\n";
        output << "}\n";
    }
};

class PEParser {
public:
    AnalysisResult parse(const std::string& filePath) const {
        BinaryReader reader(filePath);
        AnalysisResult result;
        result.filePath = filePath;
        result.fileSize = reader.fileSize();

        const auto dosHeader = reader.read<ImageDosHeader>(0);
        if (dosHeader.e_magic != 0x5A4D) {
            throw std::runtime_error("Input file is not a valid MZ executable.");
        }

        const std::size_t ntHeaderOffset = static_cast<std::size_t>(dosHeader.e_lfanew);
        const std::uint32_t signature = reader.read<std::uint32_t>(ntHeaderOffset);
        if (signature != 0x00004550) {
            throw std::runtime_error("PE signature was not found.");
        }

        const auto fileHeader = reader.read<ImageFileHeader>(ntHeaderOffset + 4);
        result.machine = fileHeader.machine;
        result.numberOfSections = fileHeader.numberOfSections;

        const std::size_t optionalHeaderOffset = ntHeaderOffset + 4 + sizeof(ImageFileHeader);
        const std::uint16_t optionalMagic = reader.read<std::uint16_t>(optionalHeaderOffset);

        ImageDataDirectory importDirectory{};
        if (optionalMagic == 0x10B) {
            const auto optionalHeader = reader.read<ImageOptionalHeader32>(optionalHeaderOffset);
            result.isPe32Plus = false;
            result.entryPoint = optionalHeader.addressOfEntryPoint;
            result.imageBase = optionalHeader.imageBase;
            result.sizeOfImage = optionalHeader.sizeOfImage;
            result.sizeOfHeaders = optionalHeader.sizeOfHeaders;
            importDirectory = optionalHeader.dataDirectory[1];
        } else if (optionalMagic == 0x20B) {
            const auto optionalHeader = reader.read<ImageOptionalHeader64>(optionalHeaderOffset);
            result.isPe32Plus = true;
            result.entryPoint = optionalHeader.addressOfEntryPoint;
            result.imageBase = optionalHeader.imageBase;
            result.sizeOfImage = optionalHeader.sizeOfImage;
            result.sizeOfHeaders = optionalHeader.sizeOfHeaders;
            importDirectory = optionalHeader.dataDirectory[1];
        } else {
            throw std::runtime_error("Unsupported optional header format.");
        }

        const std::size_t sectionTableOffset = optionalHeaderOffset + fileHeader.sizeOfOptionalHeader;
        result.sections.reserve(fileHeader.numberOfSections);
        for (std::size_t i = 0; i < fileHeader.numberOfSections; ++i) {
            const auto sectionHeader = reader.read<ImageSectionHeader>(sectionTableOffset + i * sizeof(ImageSectionHeader));
            SectionInfo section;
            section.name = sanitizeName(sectionHeader.name, sizeof(sectionHeader.name));
            section.virtualAddress = sectionHeader.virtualAddress;
            section.virtualSize = sectionHeader.misc.virtualSize;
            section.rawSize = sectionHeader.sizeOfRawData;
            section.rawPointer = sectionHeader.pointerToRawData;
            section.characteristics = sectionHeader.characteristics;
            result.sections.push_back(section);
        }

        if (importDirectory.virtualAddress != 0) {
            parseImports(reader, importDirectory.virtualAddress, result.sections, result.isPe32Plus, result.imports);
        }

        return result;
    }

private:
    static std::string sanitizeName(const char* rawName, std::size_t length) {
        std::string name(rawName, rawName + length);
        const auto endIt = std::find(name.begin(), name.end(), '\0');
        name.erase(endIt, name.end());
        return name;
    }

    static std::size_t rvaToOffset(std::uint32_t rva, const std::vector<SectionInfo>& sections) {
        for (const auto& section : sections) {
            const std::uint32_t maxSize = std::max(section.virtualSize, section.rawSize);
            if (rva >= section.virtualAddress && rva < section.virtualAddress + maxSize) {
                return static_cast<std::size_t>(section.rawPointer + (rva - section.virtualAddress));
            }
        }
        throw std::runtime_error("Unable to map RVA to file offset.");
    }

    static void parseImports(
        const BinaryReader& reader,
        std::uint32_t importDirectoryRva,
        const std::vector<SectionInfo>& sections,
        bool isPe32Plus,
        std::vector<ImportEntry>& imports) {

        std::size_t descriptorOffset = rvaToOffset(importDirectoryRva, sections);
        while (true) {
            const auto descriptor = reader.read<ImageImportDescriptor>(descriptorOffset);
            if (descriptor.originalFirstThunk == 0 && descriptor.name == 0 && descriptor.firstThunk == 0) {
                break;
            }

            ImportEntry importEntry;
            importEntry.library = reader.readString(rvaToOffset(descriptor.name, sections));

            const std::uint32_t thunkRva = descriptor.originalFirstThunk != 0 ? descriptor.originalFirstThunk : descriptor.firstThunk;
            std::size_t thunkOffset = rvaToOffset(thunkRva, sections);

            if (isPe32Plus) {
                while (true) {
                    const auto thunk = reader.read<ImageThunkData64>(thunkOffset);
                    if (thunk.addressOfData == 0) {
                        break;
                    }
                    const std::uint64_t ordinalFlag = 0x8000000000000000ULL;
                    if ((thunk.addressOfData & ordinalFlag) != 0) {
                        importEntry.functions.push_back("ordinal_" + std::to_string(thunk.addressOfData & 0xFFFFULL));
                    } else {
                        const std::size_t importByNameOffset = rvaToOffset(static_cast<std::uint32_t>(thunk.addressOfData), sections);
                        const auto importByName = reader.read<ImageImportByName>(importByNameOffset);
                        (void)importByName;
                        importEntry.functions.push_back(reader.readString(importByNameOffset + sizeof(ImageImportByName)));
                    }
                    thunkOffset += sizeof(ImageThunkData64);
                }
            } else {
                while (true) {
                    const auto thunk = reader.read<ImageThunkData32>(thunkOffset);
                    if (thunk.addressOfData == 0) {
                        break;
                    }
                    const std::uint32_t ordinalFlag = 0x80000000UL;
                    if ((thunk.addressOfData & ordinalFlag) != 0) {
                        importEntry.functions.push_back("ordinal_" + std::to_string(thunk.addressOfData & 0xFFFFUL));
                    } else {
                        const std::size_t importByNameOffset = rvaToOffset(thunk.addressOfData, sections);
                        const auto importByName = reader.read<ImageImportByName>(importByNameOffset);
                        (void)importByName;
                        importEntry.functions.push_back(reader.readString(importByNameOffset + sizeof(ImageImportByName)));
                    }
                    thunkOffset += sizeof(ImageThunkData32);
                }
            }

            imports.push_back(importEntry);
            descriptorOffset += sizeof(ImageImportDescriptor);
        }
    }
};

} // namespace aegis

int main(int argc, char* argv[]) {
    try {
        if (argc < 2) {
            std::cerr << "Usage: pe_analyzer <input_pe_file> [output_json]\n";
            return 1;
        }

        const std::string inputPath = argv[1];
        const std::string outputPath = argc > 2 ? argv[2] : "analysis_results.json";

        const aegis::PEParser parser;
        const auto result = parser.parse(inputPath);
        aegis::JsonWriter::write(result, outputPath);

        std::cout << "Analysis complete. Results written to: " << outputPath << "\n";
        return 0;
    } catch (const std::exception& exception) {
        std::cerr << "Error: " << exception.what() << "\n";
        return 2;
    }
}
