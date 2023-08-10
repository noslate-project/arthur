/* supports lz4 compress.
 */

#include "inc.h"
#include "lz4.h"

namespace arthur {

const char* szBlockType(BlockType t)
{
#define V(a,b) case a: return b;
    switch (t) {
        BLOCK_TYPE_LIST(V)
        default:
            break;
    }
#undef V
    assert(0);
    return NULL;
}

Lz4Stream::Lz4Stream(lz4_mode mode) :
    _block_index(0), _file(NULL), _enc(NULL), _dec(NULL)
{
    _mode = mode;
    _size_real = 0;
    _size_file = 0;
}

Lz4Stream::~Lz4Stream()
{
    if (_file) {
        Close();
    }

    if (_enc) {
        LZ4_freeStream(_enc);
        _enc = NULL;
    }

    if (_dec) {
        LZ4_freeStreamDecode(_dec);
        _dec = NULL;
    }
}

int Lz4Stream::Open(const char *file) 
{   
    if (_mode == LZ4_Compress) {
        _file = fopen(file, "wb");
        if (!_file) {
            error("Fail to open file: %s", file);
            return -1;
        }

        _enc = LZ4_createStream();
        if(!_enc) {
            error("Fail to create encode stream");
            return -1;
        }

        LZ4_stream_t *lz4strm = LZ4_initStream(_enc, sizeof(*_enc));
        if(!lz4strm) {
            error("Fail to init encode stream");
            return -1;
        }
        
    } else if (_mode == LZ4_Decompress) {
        _file = fopen(file, "rb");
        if (!_file) {
            error("Fail to open file: %s", file);
            return -1;
        }

        _dec = LZ4_createStreamDecode();
        if(!_dec) {
            error("Fail to create decode stream");
            return -1;
        }

        // 1 for okay and 0 for error
        if(!(LZ4_setStreamDecode(_dec, NULL, 0))) {
            error("Fail to set decode stream ");
            return -1;
        }
    } else {
        assert(0);
    }

    return 0;
}

void Lz4Stream::Close()
{
    if (_enc) {
        Flush();
    }

    fclose(_file);
    _file = NULL;
}

// file postion
int Lz4Stream::Seek(long n)
{
    return fseek(_file, n, SEEK_SET);
}

long Lz4Stream::Tell()
{
    return ftell(_file);
}

int Lz4Stream::Peek(char *out, size_t n)
{
    long save = Tell();
    int rc = ReadRaw(out, n);
    Seek(save);
    return rc;
}

// raw function for file access
int Lz4Stream::WriteRaw(const char *s, size_t n)
{
    size_t rc = fwrite(s, 1, n, _file);
    assert (rc == n);
    return rc;
}

int Lz4Stream::ReadRaw(char *out, size_t n)
{
    return fread(out, 1, n, _file);
}

// write stream
int Lz4Stream::Flush()
{
    // empty 
    Block& block = CurrentBlock();
    if (block.isEmpty()) {
        // do nothing
        return 0; 
    }
 
    // compress and write to fd 
    BlockHeader hdr;
    hdr.block_type = _block_type;
    int rc = Compress(block, hdr);
    if (rc < 0) {
        error("Compress failed.");
        return rc;
    }

    return 0;
}

int Lz4Stream::SetBlock(BlockType type)
{
    _block_type = type; 
    return 0;
}

/* write s for n bytes to file
 */
int Lz4Stream::Write(const char *s, size_t n)
{
    // enough room 
    Block& block = CurrentBlock();
    if (n <= block.Available()) {
        //printf("block %d %d\n", block.Available(), block.Size());
        return block.Write(s, n);
    }

    // begin a new block
    Flush();

    // one block
    if (n < BLOCK_SIZE) {
        Block& block = CurrentBlock();
        return block.Write(s, n); 
    }

    // write blocks
    assert(0);
    return n;
}

/* write blocks and flush.
 */
int Lz4Stream::WriteBlock(const char *s, size_t n, BlockType t)
{
    int rc;
    size_t m = 0;
    
    // get a new block
    Flush();
    
    BlockHeader block_hdr;
    block_hdr.block_type = t;
    for (m = 0; m < n; ) {
        Block& block = CurrentBlock();
        block.Clear();

        rc = block.Write(s+m, MIN(BLOCK_SIZE, n-m));
        if (rc < 0) {
            error("block write failed");
            return -1;
        }

        m += rc;
        rc = Compress(block, block_hdr);
        assert(rc > 0); 

        // more than one block
        block_hdr.prev_cont = 1;
    }

    return m;
}

// compress buffer and flush to fd.
int Lz4Stream::Compress(Block& block, BlockHeader& hdr)
{
    char buf[LZ4_COMPRESSBOUND(BLOCK_SIZE)];

    if (block.isEmpty()) {
        return 0;
    }

    int rc;
    size_t len;
    len = LZ4_compress_fast_continue(_enc, block.rBuf(), buf, block.Length(), sizeof(buf), 1);
    if (len < 0) {
        error("lz4 compress failed (%ld)\n", len);
        return -1;
    }

    _size_real += block.Length();
    _size_file += len;

    // write block header
    hdr.size = len;
    rc = fwrite(&hdr, 1, sizeof(hdr), _file);
    if (rc < 0) {
        return -1;
    }

    // write compressed data
    rc = fwrite(buf, 1, len, _file);
    if (rc < 0) {
        return -1;
    }

    dprint("writed %lu, compress = %lu", block.Length(), len);
 
    // clear the block 
    block.Clear(); 
    
    // next block
    _block_index++;
    
    return len;
}

/* Read a block
 */
Block* Lz4Stream::ReadBlock(BlockHeader& hdr)
{
    char buf[LZ4_COMPRESSBOUND(BLOCK_SIZE)];
    int rc;

    // next block
    _block_index++;
    Block& block = CurrentBlock(); 
    block.Clear();

    // read out block size 
    rc = fread(&hdr, 1, sizeof(hdr), _file);
    assert(rc == sizeof(hdr));
  
    // tail mark 
    if (hdr.isTailMark()) {
        return NULL;
    }

    // read out compressed data
    rc = fread(buf, 1, hdr.size, _file);

    // decompress 
    rc = LZ4_decompress_safe_continue(_dec, buf, block.wBuf(), hdr.size, BLOCK_SIZE);
    if (rc < 0) {
        error("decode failed rc = %d\n", rc);
        return NULL; 
    }
    block._length = rc;
    dprint("ReadBlock size(%d), type(%d), data(%d)\n", hdr.size, hdr.block_type, rc);

    return &block;;
}

/* put a proc file to stream
 */
int Lz4Stream::PutFile(ProcFile* pf)
{
    int rc;

    // seal the current block
    Flush();

    // flat size
    uint32_t size = pf->Size();

    // TBD: remove the Raw size
    // write file size
    rc = WriteRaw((const char*)&size, sizeof(size));

    // write file context
    rc = WriteBlock((const char*)pf, size, BLOCK_TYPE_FILE);
    assert(rc > 0);

    return rc;
}

/* get proc file from stream.
 */
ProcFile* Lz4Stream::GetFile()
{
    int rc;
    uint32_t size;

    // TBD: remove the Raw Size
    // readout the file size
    rc = ReadRaw((char*)&size, sizeof(size));
    assert(rc > 0);
    
    // malloc
    ProcFile *pf = (ProcFile*)malloc(size);
    assert(pf);

    // read out the file
    BlockHeader hdr;
    char *p = (char*)pf;    

    for (uint32_t i=0; i<size; ) {
        Block *block = ReadBlock(hdr);
        if (!block) {
            break;
        }
       
        assert(hdr.block_type == BLOCK_TYPE_FILE);

        rc = block->Read(p+i, MIN(size-i, BLOCK_SIZE));
        i += rc;
    } 

    return pf;
}

void Lz4Stream::PrintStat()
{
    info("Compressed %lu bytes into %lu bytes ==> %0.2f", 
            _size_real, _size_file, (double)_size_file/_size_real*100); 
}

};
