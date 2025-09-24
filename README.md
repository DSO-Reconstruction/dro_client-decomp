Script for Ghidra naming funcions based on arguments they pass to assert or error functions in DRO decompilation.

The script is unoptimized running decompilation of whole binary on one thread and so it can take hours to process. You were warned.

It should be run after naming 4 functions:
* n_assert
* n_assert
* n_error
* n_warning

To find **n_assert**s (there are 2 of them) you can search for "NEBULA ASSERTION" string (look below).

**n_error** is the function called by n_assert with format string as first argument (see below).

**n_warning** is the function calling [IO::Console::Warning](https://github.com/gscept/nebula-trifid/blob/e7c0a0acb05eedad9ed37a72c1bdf2d658511b42/code/foundation/io/console.cc#L310). IO::Console::Warning you can recognize by it calling n_assert with it's name in argument (see below).


Ghidra tips:
1. *S* is shortcut for search memory.
2. [menu bar] *Window -> Function Call Trees* - may be useful.
3. *Window -> Script Manager* - is where you can manage script directories and run scripts.\


## *the below*
example n_assert decomp:
```cpp
void n_assert(undefined8 param_1,undefined8 param_2,undefined4 param_3,undefined8 param_4) {
   undefined1 *puVar1;
   undefined1 local_48 [48];
   undefined1 *local_18;
   undefined4 local_10;
   undefined4 local_c;
   
   if (DAT_14136c990 != NULL) {
                    // WARNING: Could not recover jumptable at 0x000140c6b53c. Too many branches
                    // WARNING: Treating indirect jump as call
      (*DAT_14136c990)();
      return;
   }
   if (DAT_14136e380 == 0) {
      local_18 = NULL;
      local_10 = 0;
      local_c = 0;
      local_48[0] = 0;
      FUN_140c6d148(local_48,"*** NEBULA ASSERTION ***\nexpression: %s\nfile: %s\nline: %d\nfunc: %s\n",param_1,param_2,
                    param_3,param_4);
      puVar1 = local_48;
      if (local_18 != NULL) {
         puVar1 = local_18;
      }
      FUN_140c71c1c(puVar1);
      if (local_18 != NULL) {
         Memory::Free(7);
      }
   }
   else {
      n_error("*** NEBULA ASSERTION ***\nexpression: %s\nfile: %s\nline: %d\nfunc: %s\n",param_1,param_2,param_3,param_4
             );
   }
   return;
}
```


example n_warning decomp:
```cpp
void n_warning(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4) {
   undefined8 uVar1;
   undefined8 *puVar2;
   undefined8 local_res10;
   undefined8 local_res18;
   undefined8 local_res20;
   
   local_res10 = param_2;
   local_res18 = param_3;
   local_res20 = param_4;
   if (DAT_14136e380 == 0) {
      uVar1 = __acrt_iob_func(1);
      puVar2 = (undefined8 *)FUN_1406a9908();
      FID_conflict:__stdio_common_vfwprintf(*puVar2,uVar1,param_1,0,&local_res10);
   }
   else {
      IO::Console::Warning(DAT_14136e380,param_1,&local_res10);
   }
   return;
}

```
example IO::Console::Warning decomp:
```cpp
void IO::Console::Warning(longlong param_1,undefined8 param_2,undefined8 param_3) {
   undefined8 uVar1;
   longlong *plVar2;
   int iVar3;
   
   EnterCriticalSection((LPCRITICAL_SECTION)(param_1 + 24));
   iVar3 = 0;
   if (*(char *)(param_1 + 96) == '\0') {
      n_assert("this->IsOpen()",
               "C:\\jenkins-slave\\workspace\\dro.OmegaPipe.windows_client\\nebula3\\code\\foundation\\io\\console.cc",
               323,"void __cdecl IO::Console::Warning(const char *,char *)");
   }
   if (0 < *(int *)(param_1 + 72)) {
      do {
         uVar1 = Core::Ptr6IO_ConsoleHandler99::operator[](param_1 + 64,iVar3);
         plVar2 = (longlong *)Core::Ptr6IO_ConsoleHandler9_operator-9(uVar1);
         (**(code **)(*plVar2 + 80))(plVar2,param_2,param_3);
         iVar3 += 1;
      } while (iVar3 < *(int *)(param_1 + 72));
   }
                    // WARNING: Could not recover jumptable at 0x000140ca1972. Too many branches
                    // WARNING: Treating indirect jump as call
   LeaveCriticalSection((LPCRITICAL_SECTION)(param_1 + 24));
   return;
}

```

