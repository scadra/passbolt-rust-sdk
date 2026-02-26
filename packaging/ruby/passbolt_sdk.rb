# Entry point of the gem: `require "passbolt_sdk"`, then `PassboltFfi.…`.
require "ffi"

# The native library of this platform, shipped under lib/native/<os>-<arch>/.
PASSBOLT_FFI_LIBRARY = File.expand_path(
  "native/#{FFI::Platform::OS}-#{FFI::Platform::ARCH}/#{FFI.map_library_name('passbolt_ffi')}",
  __dir__
)

require_relative "passbolt_ffi"
