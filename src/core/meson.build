core_sources = files('CookieOctets.cpp', 'FileDescriptor.cpp', 'FoldedSubstringMatcher.cpp', 'FormFields.cpp', 'HostCookie.cpp', 'HttpToken.cpp', 'LibraryVersion.cpp', 'PortableSemaphore.cpp', 'QueryParams.cpp', 'RequestCookies.cpp', 'SecretBuffer.cpp', 'SemaphorePermit.cpp', 'Utf8.cpp', )

    core_lib = static_library('merovingian-core', core_sources, include_directories : inc, dependencies: [libsodium_dep, dl_dep], )
