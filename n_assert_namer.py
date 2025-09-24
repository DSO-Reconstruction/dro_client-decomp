#@author BaalNetbek x o3 mini
#@category Drakensang
#@keybinding 
#@menupath 
#@toolbar 

import re
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.symbol import SourceType
from time import time

def ensureTypesDefined(sigStr):
    """
    Look for type keywords (class/struct) in the signature string.
    For each type (e.g. "class Network::NetStream") that is not already defined
    in the DataTypeManager, define a placeholder StructureDataType.
    """
    dtm = currentProgram.getDataTypeManager()
    type_pattern = re.compile(r'\b(?:class|struct)\s+([\w:]+)')
    for m in type_pattern.finditer(sigStr):
        typeName = m.group(1).strip()
        found = False
        for dt in dtm.getAllDataTypes():
            if dt.getName() == typeName:
                found = True
                break
        if not found:
            try:
                from ghidra.program.model.data import StructureDataType, DataTypeConflictHandler
                placeholder = StructureDataType(typeName, 0)
                dtm.addDataType(placeholder, DataTypeConflictHandler.DEFAULT_HANDLER)
                print("Defined placeholder type for: " + typeName)
            except Exception as e:
                print("Failed to define placeholder for type {}: {}".format(typeName, e))

def replace_in_brackets(text, old="::", new ="_" ):
    match = re.search(r"<(.*)>", text)
    if match:
        substring_to_modify = match.group(1)
        modified_substring = substring_to_modify.replace(old, new)
        result = text[:match.start(1)] + modified_substring + text[match.end(1):]
        return result
    else:
        return text               
                
def getSignatureFromNAssert(decompiledText):
    reguex = r'n_assert\s*\(\s*"[^"]+"\s*,(?:\s*"[^"]+"\s*,){1,2}\s*[^,]+,\s*"([^"]*\s+([\w:]*(?:<[\s\w:,<>]*>)?[\w:]*(?:\s\[\])?\s*(?:operator .|operator ..)?)\([^"]*\))(?:\s\w*)?"' # v3
    #reguex = r'n_assert\s*\(\s*"[^"]+"\s*,\s*"[^"]+"\s*,\s*[^,]+,\s*"([^":]+\s([\w:]*(?:<[\s\w:,<>]*>)?[\w:]*(?:\s\[\])?)\s*\([^"]*\))(?:\s\w*)?"' # v2
    #reguex = r'n_assert\s*\(\s*"[^"]+"\s*,\s*"[^"]+"\s*,\s*[^,]+,\s*"([^"]+\([^"]*\))"' # v1

    pattern = re.compile(reguex, re.DOTALL)
    
    m = pattern.findall(decompiledText)
    if m != None:
        #matches = [extractQualifiedName(mat) for mat in m] # for full signature
        if len(set([n[1] for n in m])) == 1 and str(m[0][1]).split('::')[-1] != 'Instance':
                ensureTypesDefined(m[0][0])
                sig = m[0][1]
                sig = replace_in_brackets(sig)
                sig = sig.replace("class ", "")
                sig = sig.replace(" ", "")
                sig = sig.replace("<", "6")
                sig = sig.replace(">", "9")
                sig = sig.replace(',', '1')
                return sig
        for n in m:
            ensureTypesDefined(n[0])            
    return None
    
def getSignatureFromNWarrning(decompiledText):
	pattern = re.compile(r'(?:(?:n_warrning)|(?:n_error))\s*\(\s*"(([\w|:]*)\([^"]*\)[^"]*)"', re.DOTALL)
	m = pattern.search(decompiledText)
	if m:
		return m.group(2)
	return None

def main():
    decompInterface = DecompInterface()
    decompInterface.openProgram(currentProgram)
    
    renamed_count = 0
    for function in currentProgram.getFunctionManager().getFunctions(True):
        origName = function.getName()
        # Only process functions with a decompiler-generated name.
        if not origName.startswith("FUN_"):
            continue

        # max. 60 seconds for decomp
        result = decompInterface.decompileFunction(function, 20, monitor)
        if not result.decompileCompleted():
            print("Decompilation failed for function: " + origName)
            continue
        decompiledText = result.getDecompiledFunction().getC()
        
        properName = getSignatureFromNWarrning(decompiledText)
        if properName is None:
            properName = getSignatureFromNAssert(decompiledText)
        
        if properName:
            try:
                function.setName(properName, SourceType.USER_DEFINED)
                print("Renamed function {} to {}".format(origName, properName))
                renamed_count += 1
            except Exception as e:
                print("Error renaming {}: {}".format(origName, e))
    print("Renamed {} functions.".format(renamed_count))

if __name__ == "__main__":
    start_time = time()
    main()
    print("n_assert_namer run for {:.2f} seconds".format(time() - start_time))
