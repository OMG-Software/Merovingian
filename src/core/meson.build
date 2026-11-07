core_sources = files('file_descriptor.cpp', 'folded_substring.cpp', 'library_version.cpp', 'portable_semaphore.cpp', 'query_params.cpp', 'secret_buffer.cpp', 'SemaphorePermit.cpp', )

    core_lib = static_library('merovingian-core', core_sources, include_directories : inc, dependencies: [libsodium_dep, dl_dep], )
