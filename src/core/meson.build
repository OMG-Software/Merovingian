core_sources = files('FileDescriptor.cpp', 'FoldedSubstringMatcher.cpp', 'LibraryVersion.cpp', 'PortableSemaphore.cpp', 'query_params.cpp', 'SecretBuffer.cpp', 'SemaphorePermit.cpp', )

    core_lib = static_library('merovingian-core', core_sources, include_directories : inc, dependencies: [libsodium_dep, dl_dep], )
