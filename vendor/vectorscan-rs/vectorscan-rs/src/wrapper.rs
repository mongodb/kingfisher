use crate::error::{AsResult, Error};
use bitflags::bitflags;
use foreign_types::{foreign_type, ForeignType};
use std::{ffi::CString, mem::MaybeUninit, ptr};
use vectorscan_rs_sys as hs;

foreign_type! {
    #[derive(Debug)]
    unsafe type CompileError: Send + Sync {
        type CType = hs::hs_compile_error_t;
        fn drop = compile_error_drop;
    }

    #[derive(Debug)]
    pub unsafe type Database: Send + Sync {
        type CType = hs::hs_database_t;
        fn drop = database_drop;
    }

    #[derive(Debug)]
    pub unsafe type Scratch: Send + Sync {
        type CType = hs::hs_scratch_t;
        fn drop = scratch_drop;
    }
}

unsafe fn database_drop(v: *mut hs::hs_database_t) {
    let res = hs::hs_free_database(v);
    if res != hs::HS_SUCCESS as hs::hs_error_t {
        panic!("hs_free_database failed: {res}");
    }
}

unsafe fn scratch_drop(v: *mut hs::hs_scratch_t) {
    let res = hs::hs_free_scratch(v);
    if res != hs::HS_SUCCESS as hs::hs_error_t {
        panic!("hs_free_scratch failed: {res}");
    }
}

unsafe fn compile_error_drop(v: *mut hs::hs_compile_error_t) {
    let res = hs::hs_free_compile_error(v);
    if res != hs::HS_SUCCESS as hs::hs_error_t {
        panic!("hs_free_compile_error failed: {res}");
    }
}

bitflags! {
    #[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Flag: u32 {
        const CASELESS = hs::HS_FLAG_CASELESS;
        const DOTALL = hs::HS_FLAG_DOTALL;
        const MULTILINE = hs::HS_FLAG_MULTILINE;
        const SINGLEMATCH = hs::HS_FLAG_SINGLEMATCH;
        const ALLOWEMPTY = hs::HS_FLAG_ALLOWEMPTY;
        const UTF8 = hs::HS_FLAG_UTF8;
        const UCP = hs::HS_FLAG_UCP;
        const PREFILTER = hs::HS_FLAG_PREFILTER;
        const SOM_LEFTMOST = hs::HS_FLAG_SOM_LEFTMOST;
        const COMBINATION = hs::HS_FLAG_COMBINATION;
        const QUIET = hs::HS_FLAG_QUIET;
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Pattern {
    expression: Vec<u8>,
    flags: Flag,
    id: Option<u32>,
}

impl Pattern {
    pub fn new(expression: Vec<u8>, flags: Flag, id: Option<u32>) -> Self {
        Self {
            expression,
            flags,
            id,
        }
    }
}

impl Database {
    pub fn new(patterns: Vec<Pattern>, mode: ScanMode) -> Result<Self, Error> {
        let mut c_exprs = Vec::with_capacity(patterns.len());
        let mut c_flags = Vec::with_capacity(patterns.len());
        let mut c_ids = Vec::with_capacity(patterns.len());
        for Pattern {
            expression,
            flags,
            id,
        } in patterns
        {
            c_exprs.push(CString::new(expression)?);
            c_flags.push(flags.bits());
            c_ids.push(id.unwrap_or(0));
        }

        let mut db = MaybeUninit::zeroed();
        let mut err = MaybeUninit::zeroed();
        unsafe {
            hs::hs_compile_ext_multi(
                c_exprs
                    .iter()
                    .map(|expr| expr.as_ptr())
                    .collect::<Vec<_>>()
                    .as_ptr(),
                c_flags.as_ptr(),
                c_ids.as_ptr(),
                ptr::null(),
                c_exprs.len() as u32,
                mode.bits(),
                ptr::null(),
                db.as_mut_ptr(),
                err.as_mut_ptr(),
            )
            .ok()
            .map_err(|_e| {
                // The details of error value `_e` are stored in `err`; convert that and ignore `_e`
                let err = CompileError::from_ptr(err.assume_init());
                Error::HyperscanCompile(err.message(), err.expression())
            })?;
            Ok(Database::from_ptr(db.assume_init()))
        }
    }

    /// Serializes the database using `hs_serialize_database`.
    pub fn serialize(&self) -> Result<SerializedDatabase, Error> {
        let mut bytes = MaybeUninit::zeroed();
        let mut length = MaybeUninit::zeroed();

        unsafe {
            hs::hs_serialize_database(self.0.as_ptr(), bytes.as_mut_ptr(), length.as_mut_ptr())
                .ok()
                .map(|()| SerializedDatabase {
                    bytes: bytes.assume_init(),
                    length: length.assume_init(),
                })
        }
    }

    /// Deserializes a database using `hs_deserialize_database`.
    pub fn deserialize(sdb: SerializedDatabase) -> Result<Self, Error> {
        let mut db_ptr = MaybeUninit::zeroed();
        unsafe {
            hs::hs_deserialize_database(sdb.bytes, sdb.length, db_ptr.as_mut_ptr())
                .ok()
                .map(|()| Database::from_ptr(db_ptr.assume_init()))
        }
    }

    /// Gets the size of the database in bytes using `hs_database_size`.
    pub fn size(&self) -> Result<usize, Error> {
        let mut database_size = MaybeUninit::zeroed();
        unsafe {
            hs::hs_database_size(self.0.as_ptr(), database_size.as_mut_ptr())
                .ok()
                .map(|()| database_size.assume_init())
        }
    }

    /// Gets the required size in bytes for a stream for the database using `hs_stream_size`.
    pub fn stream_size(&self) -> Result<usize, Error> {
        let mut stream_size = MaybeUninit::zeroed();
        unsafe {
            hs::hs_stream_size(self.0.as_ptr(), stream_size.as_mut_ptr())
                .ok()
                .map(|()| stream_size.assume_init())
        }
    }
}

/// Creates a deep copy of the database via serialization followed by deserialization.
impl Clone for Database {
    fn clone(&self) -> Self {
        self.serialize().unwrap().deserialize().unwrap()
    }
}

#[derive(Debug)]
pub struct SerializedDatabase {
    bytes: *mut std::os::raw::c_char,
    length: usize,
}

impl SerializedDatabase {
    #[inline]
    pub fn deserialize(self) -> Result<Database, Error> {
        Database::deserialize(self)
    }

    /// Gets the size in bytes required to deserialize this database using
    /// `hs_serialized_database_size`.
    pub fn deserialized_size(&self) -> Result<usize, Error> {
        let mut deserialized_size = MaybeUninit::zeroed();
        unsafe {
            hs::hs_serialized_database_size(self.bytes, self.length, deserialized_size.as_mut_ptr())
                .ok()
                .map(|()| deserialized_size.assume_init())
        }
    }
}

impl Drop for SerializedDatabase {
    fn drop(&mut self) {
        // XXX should technically call the deallocator function set in `hs_set_misc_allocator`,
        // but we never call that here, and the defaults are malloc/free
        unsafe {
            libc::free(self.bytes as *mut libc::c_void);
        }
    }
}

impl Clone for Scratch {
    fn clone(&self) -> Self {
        let mut scratch = MaybeUninit::zeroed();
        unsafe {
            hs::hs_clone_scratch(self.0.as_ptr(), scratch.as_mut_ptr())
                .ok()
                .map(|()| Scratch::from_ptr(scratch.assume_init()))
                .unwrap()
        }
    }
}

impl Scratch {
    pub fn new(database: &Database) -> Result<Self, Error> {
        let mut scratch = MaybeUninit::zeroed();
        unsafe {
            hs::hs_alloc_scratch(database.as_ptr(), scratch.as_mut_ptr())
                .ok()
                .map(|()| Scratch::from_ptr(scratch.assume_init()))
        }
    }

    /// Gets the size of the scratch in bytes using `hs_scratch_size`.
    pub fn size(&self) -> Result<usize, Error> {
        let mut scratch_size = MaybeUninit::zeroed();
        unsafe {
            hs::hs_scratch_size(self.0.as_ptr(), scratch_size.as_mut_ptr())
                .ok()
                .map(|()| scratch_size.assume_init())
        }
    }
}

impl CompileError {
    fn message(&self) -> String {
        unsafe {
            let err = self.0.as_ptr();

            std::ffi::CStr::from_ptr((*err).message)
                .to_str()
                .unwrap()
                .into()
        }
    }
    fn expression(&self) -> i32 {
        unsafe { (*self.0.as_ptr()).expression }
    }
}

bitflags! {
    #[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
    pub struct ScanMode: u32 {
        const BLOCK = hs::HS_MODE_BLOCK;
        const VECTORED = hs::HS_MODE_VECTORED;
        const STREAM = hs::HS_MODE_STREAM;
        const SOM_SMALL = hs::HS_MODE_SOM_HORIZON_SMALL;
        const SOM_MEDIUM = hs::HS_MODE_SOM_HORIZON_MEDIUM;
        const SOM_LARGE = hs::HS_MODE_SOM_HORIZON_LARGE;
    }
}
