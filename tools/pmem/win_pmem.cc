/*
Copyright 2015 Google Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.  You may obtain a copy of the
License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied.  See the License for the
specific language governing permissions and limitations under the License.
*/
#include "windows.h"
#undef ERROR

#include "win_pmem.h"

#include <functional>
#include <string>

#include <yaml-cpp/yaml.h>


#define BUFF_SIZE 1024*1024

/* Some utility functions. */

static AFF4Status CreateChildProcess(
    const string &command, HANDLE stdout_wr) {

  PROCESS_INFORMATION piProcInfo;
  STARTUPINFO siStartInfo;
  BOOL bSuccess = FALSE;

  // Set up members of the PROCESS_INFORMATION structure.
  ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));

  // Set up members of the STARTUPINFO structure.
  // This structure specifies the STDIN and STDOUT handles for redirection.
  ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
  siStartInfo.cb = sizeof(STARTUPINFO);
  siStartInfo.hStdInput = NULL;
  siStartInfo.hStdOutput = stdout_wr;
  siStartInfo.hStdError = stdout_wr;
  siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

  LOG(INFO) << "Launching " << command;

  // Create the child process.
  bSuccess = CreateProcess(
      NULL,
      const_cast<char *>(command.c_str()),       // command line
      NULL,          // process security attributes
      NULL,          // primary thread security attributes
      TRUE,          // handles are inherited
      0,             // creation flags
      NULL,          // use parent's environment
      NULL,          // use parent's current directory
      &siStartInfo,  // STARTUPINFO pointer
      &piProcInfo);  // receives PROCESS_INFORMATION

  // If an error occurs, exit the application.
  if (!bSuccess) {
    LOG(ERROR) << "Unable to launch process: " << GetLastErrorMessage();
    return IO_ERROR;
  }

  // Close handles to the child process and its primary thread.
  // Some applications might keep these handles to monitor the status
  // of the child process, for example.
  CloseHandle(piProcInfo.hProcess);
  CloseHandle(piProcInfo.hThread);
  CloseHandle(stdout_wr);

  return STATUS_OK;
}

static string _GetTempPath() {
  CHAR path[MAX_PATH + 1];
  CHAR filename[MAX_PATH];

  // Extract the driver somewhere temporary.
  if (!GetTempPath(MAX_PATH, path)) {
    LOG(ERROR) << "Unable to determine temporary path.";
    return "";
  }

  LOG(INFO) << "Temp path " << path;

  // filename is now the random path.
  GetTempFileNameA(path, "pmem", 0, filename);

  return filename;
}

static DWORD _GetSystemArch() {
  SYSTEM_INFO sys_info;
  ZeroMemory(&sys_info, sizeof(sys_info));

  GetNativeSystemInfo(&sys_info);

  return sys_info.wProcessorArchitecture;
}

static string GetDriverName() {
  switch (_GetSystemArch()) {
    case PROCESSOR_ARCHITECTURE_AMD64:
      return "winpmem_x64.sys";
      break;

    case PROCESSOR_ARCHITECTURE_INTEL:
      return "winpmem_x86.sys";
      break;

    default:
      LOG(FATAL) << "I dont know what arch I am running on?";
  }
}

AFF4Status WinPmemImager::GetMemoryInfo(PmemMemoryInfo *info) {
  // We issue a DeviceIoControl() on the raw device handle to get the metadata.
  DWORD size;

  memset(info, 0, sizeof(*info));

  AFF4ScopedPtr<FileBackedObject> device_stream = resolver.AFF4FactoryOpen
      <FileBackedObject>(device_urn);

  if (!device_stream) {
    LOG(ERROR) << "Can not open device " << device_urn.SerializeToString();
    return IO_ERROR;
  }

  // Set the acquisition mode.
  if (acquisition_mode == PMEM_MODE_AUTO) {
    // For 64 bit systems we use PTE remapping.
    if (_GetSystemArch() == PROCESSOR_ARCHITECTURE_AMD64) {
      acquisition_mode = PMEM_MODE_PTE;
    } else {
      acquisition_mode = PMEM_MODE_PHYSICAL;
    }
  }

  // Set the acquisition mode.
  if (!DeviceIoControl(device_stream->fd, PMEM_CTRL_IOCTRL, &acquisition_mode,
                       sizeof(acquisition_mode), NULL, 0, &size, NULL)) {
    LOG(ERROR) << "Failed to set acquisition mode: " << GetLastErrorMessage();
    return IO_ERROR;
  } else {
    LOG(INFO) << "Setting acquisition mode " << acquisition_mode;
  }

  // Get the memory ranges.
  if (!DeviceIoControl(device_stream->fd, PMEM_INFO_IOCTRL, NULL, 0,
                       reinterpret_cast<char *>(info),
                       sizeof(*info), &size, NULL)) {
    LOG(ERROR) << "Failed to get memory geometry: " << GetLastErrorMessage();
    return IO_ERROR;
  }

  return STATUS_OK;
}

static void print_memory_info_(const PmemMemoryInfo &info) {
  StringIO output_stream;

  output_stream.sprintf("CR3: 0x%010llX\n %d memory ranges:\n", info.CR3,
                        info.NumberOfRuns);

  for (unsigned int i = 0; i < info.NumberOfRuns; i++) {
    output_stream.sprintf("Start 0x%08llX - Length 0x%08llX\n",
                          info.Runs[i].start, info.Runs[i].length);
  }

  std::cout << output_stream.buffer.c_str();
}


static string DumpMemoryInfoToYaml(const PmemMemoryInfo &info) {
  YAML::Emitter out;
  YAML::Node node;

  node["Imager"] = "WinPmem " PMEM_VERSION;
  YAML::Node registers_node;
  registers_node["CR3"] = info.CR3;
  node["Registers"] = registers_node;

  node["NtBuildNumber"] = info.NtBuildNumber;
  node["KernBase"] = info.KernBase;
  node["NtBuildNumberAddr"] = info.NtBuildNumberAddr;
  YAML::Node runs;
  for (size_t i = 0; i < info.NumberOfRuns; i++) {
    YAML::Node run;
    run["start"] = info.Runs[i].start;
    run["length"] = info.Runs[i].length;

    runs.push_back(run);
  }

  node["Runs"] = runs;

  out << node;
  return out.c_str();
}

// A private helper class to read from a pipe.
class _PipedReaderStream: public AFF4Stream {
 protected:
  HANDLE stdout_rd;

 public:
  explicit _PipedReaderStream(DataStore *resolver, HANDLE stdout_rd):
      AFF4Stream(resolver),
      stdout_rd(stdout_rd)
  {}

  string Read(size_t length) {
    string buffer(length, 0);
    DWORD bytes_read = buffer.size();

    if (!ReadFile(stdout_rd, &buffer[0], bytes_read, &bytes_read, NULL)) {
      return "";
    }

    readptr += bytes_read;
    return buffer;
  }

  virtual ~_PipedReaderStream() {
    CloseHandle(stdout_rd);
  }
};


AFF4Status WinPmemImager::ImagePageFile() {
  int pagefile_number = 0;

  // If the user did not specify pagefiles then do nothing.
  if (pagefiles.size() == 0)
    return CONTINUE;

  string fcat_path = _GetTempPath();
  if (fcat_path.size() == 0)
    return IO_ERROR;

  URN fcat_urn = URN::NewURNFromFilename(fcat_path);
  LOG(INFO) << "fcat_urn " << fcat_urn.SerializeToString();
  AFF4Status res = ExtractFile_(imager_urn.Append("fcat.exe"),
                                fcat_urn);

  if (res != STATUS_OK)
    return res;

  // Remember to clean up when done.
  to_be_removed.push_back(fcat_urn);

  for (string pagefile_path : pagefiles) {
    // Now shell out to fcat and copy to the output.
    SECURITY_ATTRIBUTES saAttr;
    HANDLE stdout_rd = NULL;
    HANDLE stdout_wr = NULL;

    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    // Create a pipe for the child process's STDOUT.
    if (!CreatePipe(&stdout_rd, &stdout_wr, &saAttr, 0)) {
      LOG(ERROR) << "StdoutRd CreatePipe";
      return IO_ERROR;
    }

    // Ensure the read handle to the pipe for STDOUT is not inherited.
    SetHandleInformation(stdout_rd, HANDLE_FLAG_INHERIT, 0);
    string command_line = aff4_sprintf(
        "%s %s \\\\.\\%s", fcat_path.c_str(),
        // path component.
        pagefile_path.substr(3, pagefile_path.size()).c_str(),
        // Drive letter.
        pagefile_path.substr(0, 2).c_str());

    res = CreateChildProcess(command_line, stdout_wr);
    if (res != STATUS_OK) {
      to_be_removed.clear();

      return res;
    }

    std::cout << "Preparing to run " << command_line.c_str() << "\n";
    string buffer(BUFF_SIZE, 0);
    URN volume_urn;
    AFF4Status res = GetOutputVolumeURN(volume_urn);
    if (res != STATUS_OK)
      return res;

    URN pagefile_urn = volume_urn.Append(
        URN::NewURNFromFilename(pagefile_path).Path());

    std::cout << "Output will go to " <<
        pagefile_urn.SerializeToString() << "\n";

    AFF4ScopedPtr<AFF4Stream> output_stream = GetWritableStream_(
        pagefile_urn, volume_urn);

    if (!output_stream)
      return IO_ERROR;

    resolver.Set(pagefile_urn, AFF4_CATEGORY, new URN(AFF4_MEMORY_PAGEFILE));
    resolver.Set(pagefile_urn, AFF4_MEMORY_PAGEFILE_NUM,
                 new XSDInteger(pagefile_number));


    DefaultProgress progress;
    _PipedReaderStream reader_stream(&resolver, stdout_rd);
    res = output_stream->WriteStream(&reader_stream, &progress);
    if (res != STATUS_OK)
      return res;
  }

  actions_run.insert("pagefile");
  return CONTINUE;
}

AFF4Status WinPmemImager::CreateMap_(AFF4Map *map, aff4_off_t *length) {
  PmemMemoryInfo info;
  AFF4Status res = GetMemoryInfo(&info);
  if (res != STATUS_OK)
    return res;

  // Copy the memory to the output.
  for (unsigned int i = 0; i < info.NumberOfRuns; i++) {
    PHYSICAL_MEMORY_RANGE range = info.Runs[i];

    std::cout << "Dumping Range " << i << " (Starts at " << std::hex <<
        range.start << ", length " << range.length << ")\n";

    map->AddRange(range.start, range.start, range.length, device_urn);
    *length += range.length;
  }

  return STATUS_OK;
}


// We image memory in the order of volatility - first the physical RAM, then the
// pagefile then any files that may be required.
AFF4Status WinPmemImager::ImagePhysicalMemory() {
  AFF4Status res;

  // First ensure that the driver is loaded.
  res = InstallDriver();
  if (res != CONTINUE)
    return res;

  URN output_urn;
  res = GetOutputVolumeURN(output_volume_urn);
  if (res != STATUS_OK)
    return res;

  // We image memory into this map stream.
  URN map_urn = output_volume_urn.Append("PhysicalMemory");

  AFF4ScopedPtr<AFF4Volume> volume = resolver.AFF4FactoryOpen<AFF4Volume>(
      output_volume_urn);

  // This is a physical memory image.
  resolver.Set(map_urn, AFF4_CATEGORY, new URN(AFF4_MEMORY_PHYSICAL));

  // Write the information into the image.
  AFF4ScopedPtr<AFF4Stream> information_stream = volume->CreateMember(
      map_urn.Append("information.yaml"));

  if (!information_stream) {
    LOG(ERROR) << "Unable to create memory information yaml.";
    return IO_ERROR;
  }

  PmemMemoryInfo info;
  res = GetMemoryInfo(&info);
  if (res != STATUS_OK)
    return res;

  if (information_stream->Write(DumpMemoryInfoToYaml(info)) < 0)
    return IO_ERROR;

  string format = GetArg<TCLAP::ValueArg<string>>("format")->getValue();

  if (format == "map") {
    res = WriteMapObject_(map_urn, output_volume_urn);
  } else if (format == "raw") {
    res = WriteRawFormat_(map_urn, output_volume_urn);
  } else if (format == "elf") {
    res = WriteElfFormat_(map_urn, output_volume_urn);
  }

  if (res != STATUS_OK) {
    return res;
  }

  actions_run.insert("memory");

  // Now image the pagefiles.
  res = ImagePageFile();
  if (res != CONTINUE)
    return res;

  // Also capture these by default.
  if (inputs.size() == 0) {
    LOG(INFO) << "Adding default file collections.";
    inputs.push_back("C:\\Windows\\SysNative\\drivers\\*.sys");

    // Used to bootstrap kernel GUID detection.
    inputs.push_back("C:\\Windows\\SysNative\\ntoskrnl.exe");
  }

  res = process_input();
  return res;
}

// Extract the driver file from our own volume.
AFF4Status WinPmemImager::ExtractFile_(URN input_file, URN output_file) {
  // We extract our own files from the private resolver.
  AFF4ScopedPtr<AFF4Stream> input_file_stream = private_resolver.AFF4FactoryOpen
      <AFF4Stream>(input_file);

  if (!input_file_stream) {
    LOG(FATAL) << "Unable to extract the correct driver - "
        "maybe the binary is damaged?";
  }

  private_resolver.Set(output_file, AFF4_STREAM_WRITE_MODE,
                       new XSDString("truncate"));

  AFF4ScopedPtr<AFF4Stream> outfile = private_resolver.AFF4FactoryOpen
      <AFF4Stream>(output_file);

  if (!outfile) {
    LOG(FATAL) << "Unable to create driver file.";
  }

  LOG(INFO) << "Extracted " << input_file.SerializeToString() << " to " <<
      output_file.SerializeToString();

  // These files should be small so dont worry about progress.
  AFF4Status res = input_file_stream->CopyToStream(
      *outfile, input_file_stream->Size(), &empty_progress);

  if (res == STATUS_OK)
    // We must make sure to close the file or we will not be able to load it
    // while we hold a handle to it.
    res = private_resolver.Close<AFF4Stream>(outfile);

  if (res != STATUS_OK) {
    LOG(ERROR) << "Unable to extract " << input_file.SerializeToString();
  }

  return res;
}


AFF4Status WinPmemImager::InstallDriver() {
  string driver_path;

  // We need to extract the driver somewhere temporary.
  if (!Get("driver")->isSet()) {
    driver_path = _GetTempPath();
    if (driver_path.size() == 0)
      return IO_ERROR;

    URN filename_urn = URN::NewURNFromFilename(driver_path);
    AFF4Status res = ExtractFile_(
        imager_urn.Append(GetDriverName()),   // Driver URN relative to imager.
        filename_urn);   // Where to store the driver.

    if (res != STATUS_OK)
      return res;

    // Remove this file when we are done.
    to_be_removed.push_back(filename_urn);
  } else {
    // Use the driver the user told us to.
    driver_path = GetArg<TCLAP::ValueArg<string>>("driver")->getValue();
  }

  // Now install the driver.
  UninstallDriver();   // First ensure the driver is not already installed.

  SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
  if (!scm) {
    LOG(ERROR) << "Can not open SCM. Are you administrator?";
    return IO_ERROR;
  }

  // First try to create the service.
  SC_HANDLE service = CreateService(
      scm,
      service_name.c_str(),
      service_name.c_str(),
      SERVICE_ALL_ACCESS,
      SERVICE_KERNEL_DRIVER,
      SERVICE_DEMAND_START,
      SERVICE_ERROR_NORMAL,
      driver_path.c_str(),
      NULL,
      NULL,
      NULL,
      NULL,
      NULL);

  // Maybe the service is already there - try to open it instead.
  if (GetLastError() == ERROR_SERVICE_EXISTS) {
    service = OpenService(scm, service_name.c_str(),
                                 SERVICE_ALL_ACCESS);
  }

  if (!service) {
    CloseServiceHandle(scm);
    return IO_ERROR;
  }

  if (!StartService(service, 0, NULL)) {
    if (GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
      LOG(ERROR) << "Error: StartService(), Cannot start the driver:" <<
          GetLastErrorMessage();
      CloseServiceHandle(service);
      CloseServiceHandle(scm);

      return IO_ERROR;
    }
  }

  // Remember this so we can safely unload it.
  driver_installed_ = true;

  LOG(INFO) << "Loaded Driver " << driver_path;
  device_urn = URN::NewURNFromFilename("\\\\.\\" + device_name);

  // We need write mode for issuing IO controls. Note the driver will refuse
  // write unless it is also switched to write mode.
  resolver.Set(device_urn, AFF4_STREAM_WRITE_MODE, new XSDString("append"));

  AFF4ScopedPtr<FileBackedObject> device_stream = resolver.AFF4FactoryOpen
      <FileBackedObject>(device_urn);

  if (!device_stream) {
    LOG(ERROR) << "Unable to open device: " << GetLastErrorMessage();
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return IO_ERROR;
  }

  CloseServiceHandle(service);
  CloseServiceHandle(scm);

  // Now print some info about the driver.
  PmemMemoryInfo info;
  AFF4Status res = GetMemoryInfo(&info);
  if (res != STATUS_OK)
    return res;

  print_memory_info_(info);

  actions_run.insert("load-driver");
  return CONTINUE;
}


AFF4Status WinPmemImager::UninstallDriver() {
  SC_HANDLE scm, service;
  SERVICE_STATUS ServiceStatus;

  scm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);

  if (!scm)
    return IO_ERROR;

  service = OpenService(scm, service_name.c_str(), SERVICE_ALL_ACCESS);

  if (service) {
    ControlService(service, SERVICE_CONTROL_STOP, &ServiceStatus);
  }

  DeleteService(service);
  CloseServiceHandle(service);
  std::cout << "Driver Unloaded.\n";

  actions_run.insert("unload-driver");
  return CONTINUE;
}


AFF4Status WinPmemImager::Initialize() {
  // We need to load the AFF4 volume attached to our own executable.
  HMODULE hModule = GetModuleHandleW(NULL);
  CHAR path[MAX_PATH];
  GetModuleFileNameA(hModule, path, MAX_PATH);

  AFF4ScopedPtr<ZipFile> volume = ZipFile::NewZipFile(
      &private_resolver, URN::NewURNFromFilename(path));

  if (!volume) {
    LOG(FATAL) << "Unable to extract drivers. Maybe the executable is damaged?";
  }

  LOG(INFO) << "Openning driver AFF4 volume: " <<
      volume->urn.SerializeToString();

  imager_urn = volume->urn;

  return STATUS_OK;
}


AFF4Status WinPmemImager::ParseArgs() {
  AFF4Status result = PmemImager::ParseArgs();

  // Sanity checks.
  if (result == CONTINUE && Get("load-driver")->isSet() &&
      Get("unload-driver")->isSet()) {
    LOG(ERROR) << "You can not specify both the -l and -u options together.\n";
    return INVALID_INPUT;
  }

  if (result == CONTINUE && Get("pagefile")->isSet())
    result = handle_pagefiles();

  if (result == CONTINUE && Get("mode")->isSet())
    result = handle_acquisition_mode();

  return result;
}

AFF4Status WinPmemImager::ProcessArgs() {
  AFF4Status result = CONTINUE;

  // If load-driver was issued we break here.
  if (result == CONTINUE && Get("load-driver")->isSet())
    result = InstallDriver();

  // If load-driver was issued we break here.
  if (result == CONTINUE && Get("unload-driver")->isSet())
    result = UninstallDriver();

  if (result == CONTINUE)
    result = PmemImager::ProcessArgs();

  return result;
}

WinPmemImager::~WinPmemImager() {
  // Unload the driver if we loaded it and the user specifically does not want
  // it to be left behind.
  if (driver_installed_) {
    if (Get("load-driver")->isSet()) {
      std::cout << "Memory access driver left loaded since you specified "
          "the -l flag.\n";
    } else {
      UninstallDriver();
    }
  }
}

AFF4Status WinPmemImager::handle_acquisition_mode() {
  string mode = GetArg<TCLAP::ValueArg<string>>("mode")->getValue();

  if (mode == "MmMapIoSpace") {
    acquisition_mode = PMEM_MODE_IOSPACE;
  } else if (mode == "PhysicalMemory") {
    acquisition_mode = PMEM_MODE_PHYSICAL;
  } else if (mode == "PTERemapping") {
    acquisition_mode = PMEM_MODE_PTE;
  } else {
    LOG(ERROR) << "Invalid acquisition mode specified: " << mode;
    return IO_ERROR;
  }

  return CONTINUE;
}

AFF4Status WinPmemImager::handle_pagefiles() {
  vector<string> pagefile_args = GetArg<TCLAP::MultiArgToNextFlag<string>>(
      "pagefile")->getValue();

  for (auto it : pagefile_args) {
    char path[MAX_PATH];

    if (GetFullPathName(it.c_str(), MAX_PATH, path, NULL) == 0) {
      LOG(ERROR) << "GetFullPathName failed: " << GetLastErrorMessage();
      return IO_ERROR;
    }

    pagefiles.push_back(path);
  }

  return CONTINUE;
}
