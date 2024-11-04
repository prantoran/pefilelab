import pefile

pe = pefile.PE('A.exe')

print("pe.OPTIONAL_HEADER.AddressOfEntryPoint", pe.OPTIONAL_HEADER.AddressOfEntryPoint)
print("pe.OPTIONAL_HEADER.ImageBase", pe.OPTIONAL_HEADER.ImageBase)
print("pe.FILE_HEADER.NumberOfSections", pe.FILE_HEADER.NumberOfSections)

pe.OPTIONAL_HEADER.AddressOfEntryPoint = 0xdeadbeef
pe.write(filename='file_to_write.exe')

for section in pe.sections:
  print (section.Name, hex(section.VirtualAddress),
    hex(section.Misc_VirtualSize), section.SizeOfRawData )


# If the PE file was loaded using the fast_load=True argument, we will need to parse the data directories:

pe.parse_data_directories()

for entry in pe.DIRECTORY_ENTRY_IMPORT:
  print("entry.dll:", entry.dll)
  for imp in entry.imports:
    print('\t', "imp.address:", hex(imp.address), "imp.name:", imp.name)

pe2 = pefile.PE('file_to_write.exe')
print("pe2.OPTIONAL_HEADER.AddressOfEntryPoint", pe2.OPTIONAL_HEADER.AddressOfEntryPoint)


# for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
#   print(hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal)

print(pe.dump_info())

