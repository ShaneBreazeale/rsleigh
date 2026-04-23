//! CPython 3.11 C API function signatures.
//!
//! Coverage: the subset that actually appears in shipped Python C extensions.
//! Focused on object protocol, number protocol, container protocols (list,
//! tuple, dict, set, bytes, unicode, long, float), import / module helpers,
//! error-handling helpers, iteration, argument parsing, and the few eval /
//! compile entry points that leak into extensions.

use crate::signatures::*;

pub static PYTHON_SIGNATURES: &[FuncSig] = crate::define_signatures! {
    // -- Object protocol --------------------------------------------------
    fn Py_IncRef(o: PyObjectPtr);
    fn Py_DecRef(o: PyObjectPtr);
    fn _Py_Dealloc(o: PyObjectPtr);
    fn _Py_NewReference(o: PyObjectPtr);
    fn PyObject_Type(o: PyObjectPtr) -> PyObjectPtr;
    fn PyObject_Size(o: PyObjectPtr) -> PySsizeT;
    fn PyObject_Length(o: PyObjectPtr) -> PySsizeT;
    fn PyObject_Hash(o: PyObjectPtr) -> PyHashT;
    fn PyObject_HashNotImplemented(o: PyObjectPtr) -> PyHashT;
    fn PyObject_IsTrue(o: PyObjectPtr) -> Int;
    fn PyObject_Not(o: PyObjectPtr) -> Int;
    fn PyObject_GetAttr(o: PyObjectPtr, name: PyObjectPtr) -> PyObjectPtr;
    fn PyObject_GetAttrString(o: PyObjectPtr, name: ConstCharPtr) -> PyObjectPtr;
    fn PyObject_SetAttr(o: PyObjectPtr, name: PyObjectPtr, value: PyObjectPtr) -> Int;
    fn PyObject_SetAttrString(o: PyObjectPtr, name: ConstCharPtr, value: PyObjectPtr) -> Int;
    fn PyObject_HasAttr(o: PyObjectPtr, name: PyObjectPtr) -> Int;
    fn PyObject_HasAttrString(o: PyObjectPtr, name: ConstCharPtr) -> Int;
    fn PyObject_GenericGetAttr(o: PyObjectPtr, name: PyObjectPtr) -> PyObjectPtr;
    fn PyObject_GenericSetAttr(o: PyObjectPtr, name: PyObjectPtr, value: PyObjectPtr) -> Int;
    fn PyObject_Dir(o: PyObjectPtr) -> PyObjectPtr;
    fn PyObject_Repr(o: PyObjectPtr) -> PyObjectPtr;
    fn PyObject_Str(o: PyObjectPtr) -> PyObjectPtr;
    fn PyObject_ASCII(o: PyObjectPtr) -> PyObjectPtr;
    fn PyObject_Bytes(o: PyObjectPtr) -> PyObjectPtr;
    fn PyObject_Format(o: PyObjectPtr, format_spec: PyObjectPtr) -> PyObjectPtr;
    fn PyObject_RichCompare(o1: PyObjectPtr, o2: PyObjectPtr, opid: PyRichCmpOp) -> PyObjectPtr;
    fn PyObject_RichCompareBool(o1: PyObjectPtr, o2: PyObjectPtr, opid: PyRichCmpOp) -> Int;
    fn PyObject_IsInstance(inst: PyObjectPtr, cls: PyObjectPtr) -> Int;
    fn PyObject_IsSubclass(derived: PyObjectPtr, cls: PyObjectPtr) -> Int;
    fn PyObject_GetIter(o: PyObjectPtr) -> PyObjectPtr;
    fn PyObject_Call(callable: PyObjectPtr, args: PyObjectPtr, kwargs: PyObjectPtr) -> PyObjectPtr;
    fn PyObject_CallObject(callable: PyObjectPtr, args: PyObjectPtr) -> PyObjectPtr;
    fn PyObject_CallNoArgs(callable: PyObjectPtr) -> PyObjectPtr;
    fn PyObject_CallOneArg(callable: PyObjectPtr, arg: PyObjectPtr) -> PyObjectPtr;
    fn PyObject_CallFunction(callable: PyObjectPtr, format: ConstCharPtr, ...) -> PyObjectPtr;
    fn PyObject_CallMethod(obj: PyObjectPtr, name: ConstCharPtr, format: ConstCharPtr, ...) -> PyObjectPtr;
    fn PyObject_CallFunctionObjArgs(callable: PyObjectPtr, ...) -> PyObjectPtr;
    fn PyObject_CallMethodObjArgs(obj: PyObjectPtr, name: PyObjectPtr, ...) -> PyObjectPtr;
    fn PyObject_GetItem(o: PyObjectPtr, key: PyObjectPtr) -> PyObjectPtr;
    fn PyObject_SetItem(o: PyObjectPtr, key: PyObjectPtr, value: PyObjectPtr) -> Int;
    fn PyObject_DelItem(o: PyObjectPtr, key: PyObjectPtr) -> Int;
    fn PyObject_SelfIter(o: PyObjectPtr) -> PyObjectPtr;
    fn PyObject_GetBuffer(o: PyObjectPtr, view: VoidPtr, flags: Int) -> Int;
    fn PyBuffer_Release(view: VoidPtr);
    fn _PyObject_New(tp: PyTypeObjectPtr) -> PyObjectPtr;
    fn PyIter_Next(it: PyObjectPtr) -> PyObjectPtr;

    // -- Number protocol --------------------------------------------------
    fn PyNumber_Check(o: PyObjectPtr) -> Int;
    fn PyNumber_Add(o1: PyObjectPtr, o2: PyObjectPtr) -> PyObjectPtr;
    fn PyNumber_Subtract(o1: PyObjectPtr, o2: PyObjectPtr) -> PyObjectPtr;
    fn PyNumber_Multiply(o1: PyObjectPtr, o2: PyObjectPtr) -> PyObjectPtr;
    fn PyNumber_MatrixMultiply(o1: PyObjectPtr, o2: PyObjectPtr) -> PyObjectPtr;
    fn PyNumber_FloorDivide(o1: PyObjectPtr, o2: PyObjectPtr) -> PyObjectPtr;
    fn PyNumber_TrueDivide(o1: PyObjectPtr, o2: PyObjectPtr) -> PyObjectPtr;
    fn PyNumber_Remainder(o1: PyObjectPtr, o2: PyObjectPtr) -> PyObjectPtr;
    fn PyNumber_Divmod(o1: PyObjectPtr, o2: PyObjectPtr) -> PyObjectPtr;
    fn PyNumber_Power(o1: PyObjectPtr, o2: PyObjectPtr, o3: PyObjectPtr) -> PyObjectPtr;
    fn PyNumber_Negative(o: PyObjectPtr) -> PyObjectPtr;
    fn PyNumber_Positive(o: PyObjectPtr) -> PyObjectPtr;
    fn PyNumber_Absolute(o: PyObjectPtr) -> PyObjectPtr;
    fn PyNumber_Invert(o: PyObjectPtr) -> PyObjectPtr;
    fn PyNumber_Lshift(o1: PyObjectPtr, o2: PyObjectPtr) -> PyObjectPtr;
    fn PyNumber_Rshift(o1: PyObjectPtr, o2: PyObjectPtr) -> PyObjectPtr;
    fn PyNumber_And(o1: PyObjectPtr, o2: PyObjectPtr) -> PyObjectPtr;
    fn PyNumber_Or(o1: PyObjectPtr, o2: PyObjectPtr) -> PyObjectPtr;
    fn PyNumber_Xor(o1: PyObjectPtr, o2: PyObjectPtr) -> PyObjectPtr;
    fn PyNumber_Index(o: PyObjectPtr) -> PyObjectPtr;
    fn PyNumber_Long(o: PyObjectPtr) -> PyObjectPtr;
    fn PyNumber_Float(o: PyObjectPtr) -> PyObjectPtr;
    fn PyNumber_AsSsize_t(o: PyObjectPtr, exc: PyObjectPtr) -> PySsizeT;

    // -- Long protocol ----------------------------------------------------
    fn PyLong_FromLong(v: Long) -> PyObjectPtr;
    fn PyLong_FromUnsignedLong(v: ULong) -> PyObjectPtr;
    fn PyLong_FromLongLong(v: Long) -> PyObjectPtr;
    fn PyLong_FromUnsignedLongLong(v: ULong) -> PyObjectPtr;
    fn PyLong_FromDouble(v: ULong) -> PyObjectPtr;
    fn PyLong_FromSsize_t(v: PySsizeT) -> PyObjectPtr;
    fn PyLong_FromSize_t(v: SizeT) -> PyObjectPtr;
    fn PyLong_FromString(s: ConstCharPtr, pend: CharPtr, base: Int) -> PyObjectPtr;
    fn PyLong_AsLong(o: PyObjectPtr) -> Long;
    fn PyLong_AsUnsignedLong(o: PyObjectPtr) -> ULong;
    fn PyLong_AsLongLong(o: PyObjectPtr) -> Long;
    fn PyLong_AsUnsignedLongLong(o: PyObjectPtr) -> ULong;
    fn PyLong_AsSsize_t(o: PyObjectPtr) -> PySsizeT;
    fn PyLong_AsSize_t(o: PyObjectPtr) -> SizeT;
    fn PyLong_AsDouble(o: PyObjectPtr) -> PyObjectPtr;

    // -- Float protocol ---------------------------------------------------
    fn PyFloat_FromDouble(v: ULong) -> PyObjectPtr;
    fn PyFloat_FromString(s: PyObjectPtr) -> PyObjectPtr;
    fn PyFloat_AsDouble(o: PyObjectPtr) -> ULong;

    // -- Bool / None ------------------------------------------------------
    fn PyBool_FromLong(v: Long) -> PyObjectPtr;

    // -- Bytes protocol ---------------------------------------------------
    fn PyBytes_FromStringAndSize(s: ConstCharPtr, size: PySsizeT) -> PyObjectPtr;
    fn PyBytes_FromString(s: ConstCharPtr) -> PyObjectPtr;
    fn PyBytes_AsString(o: PyObjectPtr) -> CharPtr;
    fn PyBytes_AsStringAndSize(o: PyObjectPtr, s: VoidPtr, size: VoidPtr) -> Int;
    fn PyBytes_Size(o: PyObjectPtr) -> PySsizeT;
    fn PyBytes_Concat(bytes: PyObjectPtrPtr, other: PyObjectPtr);
    fn PyBytes_ConcatAndDel(bytes: PyObjectPtrPtr, other: PyObjectPtr);

    // -- Bytearray protocol -----------------------------------------------
    fn PyByteArray_FromStringAndSize(s: ConstCharPtr, size: PySsizeT) -> PyObjectPtr;
    fn PyByteArray_AsString(o: PyObjectPtr) -> CharPtr;
    fn PyByteArray_Size(o: PyObjectPtr) -> PySsizeT;

    // -- Unicode protocol -------------------------------------------------
    fn PyUnicode_FromString(u: ConstCharPtr) -> PyObjectPtr;
    fn PyUnicode_FromStringAndSize(u: ConstCharPtr, size: PySsizeT) -> PyObjectPtr;
    fn PyUnicode_FromFormat(format: ConstCharPtr, ...) -> PyObjectPtr;
    fn PyUnicode_DecodeUTF8(s: ConstCharPtr, size: PySsizeT, errors: ConstCharPtr) -> PyObjectPtr;
    fn PyUnicode_DecodeUTF16(s: ConstCharPtr, size: PySsizeT, errors: ConstCharPtr, byteorder: VoidPtr) -> PyObjectPtr;
    fn PyUnicode_AsUTF8(o: PyObjectPtr) -> ConstCharPtr;
    fn PyUnicode_AsUTF8String(o: PyObjectPtr) -> PyObjectPtr;
    fn PyUnicode_AsUTF8AndSize(o: PyObjectPtr, size: VoidPtr) -> ConstCharPtr;
    fn PyUnicode_AsEncodedString(unicode: PyObjectPtr, encoding: ConstCharPtr, errors: ConstCharPtr) -> PyObjectPtr;
    fn PyUnicode_Concat(left: PyObjectPtr, right: PyObjectPtr) -> PyObjectPtr;
    fn PyUnicode_Format(format: PyObjectPtr, args: PyObjectPtr) -> PyObjectPtr;
    fn PyUnicode_Join(separator: PyObjectPtr, seq: PyObjectPtr) -> PyObjectPtr;
    fn PyUnicode_Split(s: PyObjectPtr, sep: PyObjectPtr, maxsplit: PySsizeT) -> PyObjectPtr;
    fn PyUnicode_Replace(s: PyObjectPtr, substr: PyObjectPtr, replstr: PyObjectPtr, maxcount: PySsizeT) -> PyObjectPtr;
    fn PyUnicode_GetLength(unicode: PyObjectPtr) -> PySsizeT;
    fn PyUnicode_CompareWithASCIIString(unicode: PyObjectPtr, string: ConstCharPtr) -> Int;
    fn PyUnicode_InternFromString(u: ConstCharPtr) -> PyObjectPtr;
    fn PyUnicode_InternInPlace(string: PyObjectPtrPtr);

    // -- Dict protocol ----------------------------------------------------
    fn PyDict_New() -> PyObjectPtr;
    fn PyDict_Copy(dict: PyObjectPtr) -> PyObjectPtr;
    fn PyDict_Clear(dict: PyObjectPtr);
    fn PyDict_Contains(dict: PyObjectPtr, key: PyObjectPtr) -> Int;
    fn PyDict_GetItem(dict: PyObjectPtr, key: PyObjectPtr) -> PyObjectPtr;
    fn PyDict_GetItemString(dict: PyObjectPtr, key: ConstCharPtr) -> PyObjectPtr;
    fn PyDict_GetItemWithError(dict: PyObjectPtr, key: PyObjectPtr) -> PyObjectPtr;
    fn PyDict_SetItem(dict: PyObjectPtr, key: PyObjectPtr, value: PyObjectPtr) -> Int;
    fn PyDict_SetItemString(dict: PyObjectPtr, key: ConstCharPtr, value: PyObjectPtr) -> Int;
    fn PyDict_DelItem(dict: PyObjectPtr, key: PyObjectPtr) -> Int;
    fn PyDict_DelItemString(dict: PyObjectPtr, key: ConstCharPtr) -> Int;
    fn PyDict_Keys(dict: PyObjectPtr) -> PyObjectPtr;
    fn PyDict_Values(dict: PyObjectPtr) -> PyObjectPtr;
    fn PyDict_Items(dict: PyObjectPtr) -> PyObjectPtr;
    fn PyDict_Size(dict: PyObjectPtr) -> PySsizeT;
    fn PyDict_Next(dict: PyObjectPtr, ppos: VoidPtr, pkey: PyObjectPtrPtr, pvalue: PyObjectPtrPtr) -> Int;
    fn PyDict_Merge(a: PyObjectPtr, b: PyObjectPtr, override_: Int) -> Int;
    fn PyDict_Update(a: PyObjectPtr, b: PyObjectPtr) -> Int;

    // -- List protocol ----------------------------------------------------
    fn PyList_New(size: PySsizeT) -> PyObjectPtr;
    fn PyList_Size(list: PyObjectPtr) -> PySsizeT;
    fn PyList_GetItem(list: PyObjectPtr, index: PySsizeT) -> PyObjectPtr;
    fn PyList_SetItem(list: PyObjectPtr, index: PySsizeT, item: PyObjectPtr) -> Int;
    fn PyList_Insert(list: PyObjectPtr, index: PySsizeT, item: PyObjectPtr) -> Int;
    fn PyList_Append(list: PyObjectPtr, item: PyObjectPtr) -> Int;
    fn PyList_GetSlice(list: PyObjectPtr, low: PySsizeT, high: PySsizeT) -> PyObjectPtr;
    fn PyList_SetSlice(list: PyObjectPtr, low: PySsizeT, high: PySsizeT, itemlist: PyObjectPtr) -> Int;
    fn PyList_Sort(list: PyObjectPtr) -> Int;
    fn PyList_Reverse(list: PyObjectPtr) -> Int;
    fn PyList_AsTuple(list: PyObjectPtr) -> PyObjectPtr;

    // -- Tuple protocol ---------------------------------------------------
    fn PyTuple_New(size: PySsizeT) -> PyObjectPtr;
    fn PyTuple_Size(tuple: PyObjectPtr) -> PySsizeT;
    fn PyTuple_GetItem(tuple: PyObjectPtr, index: PySsizeT) -> PyObjectPtr;
    fn PyTuple_SetItem(tuple: PyObjectPtr, index: PySsizeT, item: PyObjectPtr) -> Int;
    fn PyTuple_GetSlice(tuple: PyObjectPtr, low: PySsizeT, high: PySsizeT) -> PyObjectPtr;
    fn PyTuple_Pack(n: PySsizeT, ...) -> PyObjectPtr;

    // -- Set / frozenset protocol ----------------------------------------
    fn PySet_New(iterable: PyObjectPtr) -> PyObjectPtr;
    fn PyFrozenSet_New(iterable: PyObjectPtr) -> PyObjectPtr;
    fn PySet_Add(set: PyObjectPtr, key: PyObjectPtr) -> Int;
    fn PySet_Discard(set: PyObjectPtr, key: PyObjectPtr) -> Int;
    fn PySet_Pop(set: PyObjectPtr) -> PyObjectPtr;
    fn PySet_Size(set: PyObjectPtr) -> PySsizeT;
    fn PySet_Contains(set: PyObjectPtr, key: PyObjectPtr) -> Int;

    // -- Slice ------------------------------------------------------------
    fn PySlice_New(start: PyObjectPtr, stop: PyObjectPtr, step: PyObjectPtr) -> PyObjectPtr;

    // -- Sequence protocol (abstract) ------------------------------------
    fn PySequence_Check(o: PyObjectPtr) -> Int;
    fn PySequence_Size(o: PyObjectPtr) -> PySsizeT;
    fn PySequence_Length(o: PyObjectPtr) -> PySsizeT;
    fn PySequence_Concat(o1: PyObjectPtr, o2: PyObjectPtr) -> PyObjectPtr;
    fn PySequence_Repeat(o: PyObjectPtr, count: PySsizeT) -> PyObjectPtr;
    fn PySequence_GetItem(o: PyObjectPtr, i: PySsizeT) -> PyObjectPtr;
    fn PySequence_GetSlice(o: PyObjectPtr, i1: PySsizeT, i2: PySsizeT) -> PyObjectPtr;
    fn PySequence_SetItem(o: PyObjectPtr, i: PySsizeT, v: PyObjectPtr) -> Int;
    fn PySequence_DelItem(o: PyObjectPtr, i: PySsizeT) -> Int;
    fn PySequence_SetSlice(o: PyObjectPtr, i1: PySsizeT, i2: PySsizeT, v: PyObjectPtr) -> Int;
    fn PySequence_Tuple(o: PyObjectPtr) -> PyObjectPtr;
    fn PySequence_List(o: PyObjectPtr) -> PyObjectPtr;
    fn PySequence_Fast(o: PyObjectPtr, m: ConstCharPtr) -> PyObjectPtr;
    fn PySequence_Count(o: PyObjectPtr, value: PyObjectPtr) -> PySsizeT;
    fn PySequence_Contains(o: PyObjectPtr, value: PyObjectPtr) -> Int;
    fn PySequence_Index(o: PyObjectPtr, value: PyObjectPtr) -> PySsizeT;

    // -- Mapping protocol (abstract) -------------------------------------
    fn PyMapping_Check(o: PyObjectPtr) -> Int;
    fn PyMapping_Size(o: PyObjectPtr) -> PySsizeT;
    fn PyMapping_Length(o: PyObjectPtr) -> PySsizeT;
    fn PyMapping_GetItemString(o: PyObjectPtr, key: ConstCharPtr) -> PyObjectPtr;
    fn PyMapping_SetItemString(o: PyObjectPtr, key: ConstCharPtr, v: PyObjectPtr) -> Int;
    fn PyMapping_HasKey(o: PyObjectPtr, key: PyObjectPtr) -> Int;
    fn PyMapping_HasKeyString(o: PyObjectPtr, key: ConstCharPtr) -> Int;
    fn PyMapping_Keys(o: PyObjectPtr) -> PyObjectPtr;
    fn PyMapping_Values(o: PyObjectPtr) -> PyObjectPtr;
    fn PyMapping_Items(o: PyObjectPtr) -> PyObjectPtr;

    // -- Errors -----------------------------------------------------------
    fn PyErr_SetString(type_: PyObjectPtr, message: ConstCharPtr);
    fn PyErr_SetObject(type_: PyObjectPtr, value: PyObjectPtr);
    fn PyErr_SetNone(type_: PyObjectPtr);
    fn PyErr_Format(exc: PyObjectPtr, format: ConstCharPtr, ...) -> PyObjectPtr;
    fn PyErr_Clear();
    fn PyErr_Print();
    fn PyErr_Occurred() -> PyObjectPtr;
    fn PyErr_ExceptionMatches(exc: PyObjectPtr) -> Int;
    fn PyErr_GivenExceptionMatches(given: PyObjectPtr, exc: PyObjectPtr) -> Int;
    fn PyErr_Fetch(type_: PyObjectPtrPtr, value: PyObjectPtrPtr, traceback: PyObjectPtrPtr);
    fn PyErr_Restore(type_: PyObjectPtr, value: PyObjectPtr, traceback: PyObjectPtr);
    fn PyErr_NormalizeException(exc: PyObjectPtrPtr, val: PyObjectPtrPtr, tb: PyObjectPtrPtr);
    fn PyErr_WriteUnraisable(obj: PyObjectPtr);
    fn PyErr_NewException(name: ConstCharPtr, base: PyObjectPtr, dict: PyObjectPtr) -> PyObjectPtr;
    fn PyErr_NoMemory() -> PyObjectPtr;
    fn PyErr_BadArgument() -> Int;

    // -- Import / module --------------------------------------------------
    fn PyImport_ImportModule(name: ConstCharPtr) -> PyObjectPtr;
    fn PyImport_ImportModuleLevel(name: ConstCharPtr, globals: PyObjectPtr, locals: PyObjectPtr, fromlist: PyObjectPtr, level: Int) -> PyObjectPtr;
    fn PyImport_ImportModuleEx(name: ConstCharPtr, globals: PyObjectPtr, locals: PyObjectPtr, fromlist: PyObjectPtr) -> PyObjectPtr;
    fn PyImport_ImportFrozenModule(name: ConstCharPtr) -> Int;
    fn PyImport_AddModule(name: ConstCharPtr) -> PyObjectPtr;
    fn PyImport_GetModuleDict() -> PyObjectPtr;
    fn PyModule_Create2(module: VoidPtr, apiver: Int) -> PyObjectPtr;
    fn PyModule_GetDict(module: PyObjectPtr) -> PyObjectPtr;
    fn PyModule_GetName(module: PyObjectPtr) -> ConstCharPtr;
    fn PyModule_AddObject(module: PyObjectPtr, name: ConstCharPtr, value: PyObjectPtr) -> Int;
    fn PyModule_AddIntConstant(module: PyObjectPtr, name: ConstCharPtr, value: Long) -> Int;
    fn PyModule_AddStringConstant(module: PyObjectPtr, name: ConstCharPtr, value: ConstCharPtr) -> Int;

    // -- Type / capsule ---------------------------------------------------
    fn PyType_Ready(type_: PyTypeObjectPtr) -> Int;
    fn PyType_GenericNew(type_: PyTypeObjectPtr, args: PyObjectPtr, kwds: PyObjectPtr) -> PyObjectPtr;
    fn PyType_IsSubtype(a: PyTypeObjectPtr, b: PyTypeObjectPtr) -> Int;
    fn PyCapsule_New(pointer: VoidPtr, name: ConstCharPtr, destructor: VoidPtr) -> PyObjectPtr;
    fn PyCapsule_GetPointer(capsule: PyObjectPtr, name: ConstCharPtr) -> VoidPtr;

    // -- Argument parsing -------------------------------------------------
    fn PyArg_ParseTuple(args: PyObjectPtr, format: ConstCharPtr, ...) -> Int;
    fn PyArg_ParseTupleAndKeywords(args: PyObjectPtr, kwargs: PyObjectPtr, format: ConstCharPtr, keywords: VoidPtr, ...) -> Int;
    fn PyArg_UnpackTuple(args: PyObjectPtr, name: ConstCharPtr, min: PySsizeT, max: PySsizeT, ...) -> Int;
    fn PyArg_ValidateKeywordArguments(kwargs: PyObjectPtr) -> Int;
    fn Py_BuildValue(format: ConstCharPtr, ...) -> PyObjectPtr;
    fn Py_VaBuildValue(format: ConstCharPtr, vargs: VoidPtr) -> PyObjectPtr;

    // -- Method / function creation --------------------------------------
    fn PyMethod_New(func: PyObjectPtr, self_: PyObjectPtr) -> PyObjectPtr;
    fn PyCFunction_New(ml: VoidPtr, self_: PyObjectPtr) -> PyObjectPtr;
    fn PyCFunction_NewEx(ml: VoidPtr, self_: PyObjectPtr, module: PyObjectPtr) -> PyObjectPtr;

    // -- Eval / interpreter ----------------------------------------------
    fn PyEval_GetBuiltins() -> PyObjectPtr;
    fn PyEval_GetGlobals() -> PyObjectPtr;
    fn PyEval_GetLocals() -> PyObjectPtr;
    fn PyEval_GetFrame() -> PyFrameObjectPtr;
    fn PyEval_EvalCode(co: PyObjectPtr, globals: PyObjectPtr, locals: PyObjectPtr) -> PyObjectPtr;
    fn PyEval_SaveThread() -> VoidPtr;
    fn PyEval_RestoreThread(tstate: VoidPtr);
    fn PyEval_AcquireLock();
    fn PyEval_ReleaseLock();

    // -- Gil / threads ----------------------------------------------------
    fn PyGILState_Ensure() -> Int;
    fn PyGILState_Release(state: Int);

    // -- Stderr / tracing -------------------------------------------------
    fn PySys_WriteStdout(format: ConstCharPtr, ...);
    fn PySys_WriteStderr(format: ConstCharPtr, ...);
    fn PySys_GetObject(name: ConstCharPtr) -> PyObjectPtr;
    fn PySys_SetObject(name: ConstCharPtr, v: PyObjectPtr) -> Int;

    // -- Initialization / lifetime ---------------------------------------
    fn Py_Initialize();
    fn Py_Finalize();
    fn Py_IsInitialized() -> Int;
    fn Py_GetVersion() -> ConstCharPtr;
    fn Py_ReprEnter(obj: PyObjectPtr) -> Int;
    fn Py_ReprLeave(obj: PyObjectPtr);
};
