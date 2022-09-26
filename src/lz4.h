/* supports lz4 compress.
 */

#ifndef _ARTHUR_LZ4_H_
#define _ARTHUR_LZ4_H_

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>

#include "lz4/lz4.h"

#include "inc.h"
#include "proc.h"

namespace arthur {


// lz4 block size
// 15: 32k, 16: 64k, 17: 128k
#define BLOCK_BITS  (16)
#define BLOCK_SIZE  (1<<BLOCK_BITS)

/* arthur corefile layout,
 * | File Header | Raw Information | Memory Loads | ELF Header |
 *   - File Header: arthur file format and version.
 *   - Raw Info: register set of each thread and proc files for the process.
 *   - Memory Loads: all memory regions of the process.
 *   - Elf Header: corefile's Elf header (Program Headers)
 *
 * corefile is comopressed by LZ4 blocks. 
 * | File Header | BLOCK 1 | BLOCK 2 | ...
 *
 * Block constructs,
 * | Block Header | lz4 compressed data |
 * Block Header is a 1-4 bytes long header,
 *   - indicates end of the long data. (prev_cont flag)
 *   - indicates the data type (data or file).
 *   - indicates size of compressed data. 
 * each block contains a max of BLOCK_SIZE data, may has several structruts.
 * long data has its own boundary aligned to block, and may use several blocks to store.
 *
 * Frame, insides block, represents a boundary of piece of data.
 * | Frame Header | Data |
 *   - type of the data, both reader and writer should know the size.
 */

/* Block Type 
 */
#define BLOCK_TYPE_LIST(V) \
    V(BLOCK_TYPE_STREAM, "stream") \
    V(BLOCK_TYPE_PROCESS, "process") \
    V(BLOCK_TYPE_THREAD, "thread") \
    V(BLOCK_TYPE_FILE, "file") \
    V(BLOCK_TYPE_LOADS, "loads") \
    V(BLOCK_TYPE_ELF, "elf")

#define BLOCK_TYPE_BITS (4)
#define BLOCK_TYPE_SIZE (1 << BLOCK_TYPE_BITS)
enum BlockType {
#define V(a,b) a,
    BLOCK_TYPE_LIST(V)
#undef V
    BLOCK_TYPE_MAX
};
static_assert(BLOCK_TYPE_MAX <= BLOCK_TYPE_SIZE, "block type oversize.");
const char* szBlockType(BlockType t);

/* Block Header
 */
#pragma pack(push, 1)
struct BlockHeader {
    uint32_t prev_cont:1;       // indicate whether the block is prev's continue data.
    uint32_t block_type:4;      // enum BlockType 
    uint32_t size:19;           // size of the block (compressed)

    BlockHeader() : prev_cont(0), block_type(0), size(0) {};

    static BlockHeader TailMark() {
        BlockHeader hdr;
        hdr.prev_cont = 0;
        hdr.block_type = -1;
        hdr.size = -1;
        return hdr;
    }

    bool isTailMark() {
        BlockHeader mark = TailMark();
        return prev_cont == mark.prev_cont &&
               block_type == mark.block_type &&
               size == mark.size;
    }
};
#pragma pack(pop)
static_assert(sizeof(BlockHeader) == 3, "block size oversize.");
 
/* lz4 stream based on BLOCKs, the class holds a block buffer in Ring.
 */
class Block {

public:
    Block() : _cur(0), _length(0) {};
    ~Block() {};

    // get buffer
    const char* rBuf() { 
        return _buf; 
    }

    char* wBuf() {
        return _buf;
    } 
   
    // add data to buffer 
    int Write(const char *in, size_t n) {
        if (n > Available())  {
            return -ENOSPC;
        }

        memcpy(&_buf[_length], in, n);
        _length += n; 
        return n;
    }
   
    // read out data from buffer 
    int Read(char *out, size_t n) {
        if (n > Size()) {
            return  -ENOSPC;
        }
        size_t m = MIN(n, Size());
        memcpy(out, &_buf[_cur], m);
        _cur += m;
        return m;
    }

    // read data without update cursor
    int Peek(char *out, size_t n) {
        if (n > Size()) {
            return -ENOSPC;
        }

        memcpy(out, &_buf[_cur], n);
        return n;
    }

    // bytes remain in buffer 
    size_t Size() {
        return _length - _cur;
    }

    // data length in buffer.
    size_t Length() {
        return _length;
    }

    // the maxium buffer capacity.
    size_t Capacity() {
        return BLOCK_SIZE;
    }

    size_t Available() {
        return BLOCK_SIZE - _length;
    }

    // clear all data in buffer 
    void Clear() {
        _cur = 0;
        _length = 0;
    }

    // is end of data
    bool isEnd() {
        return _cur == _length; 
    }

    // is buffer empty
    bool isEmpty() {  
        return _length == 0; 
    }

private:
    uint32_t _cur;       // cursor
    uint32_t _length;    // data length
    char _buf[BLOCK_SIZE];          // data storage

    friend class Lz4Stream;
};

/* Frame Type
 */
#define FRAME_TYPE_BITS (6)
#define FRAME_TYPE_SIZE (1 << FRAME_TYPE_BITS)
enum FrameType {
    FRAME_TYPE_UNKNOWN = 0,
    FRAME_TYPE_U32,         // 32 bits 
    FRAME_TYPE_U64,         // 64 bits 
    FRAME_TYPE_REGSET,      // elf_gregset_t
    FRAME_TYPE_FPREGSET,    // elf_fpregset_t
    FRAME_TYPE_SIGINFO,     // siginfo_t
    FRAME_TYPE_X86STATE,    // X86_XSTATE
    FRAME_TYPE_PROC_CMDLINE,  // /proc/<pid>/cmdline 
    FRAME_TYPE_PROC_STAT,     // /proc/<pid>/stat
    FRAME_TYPE_PROC_MAPS,     // /proc/<pid>/maps 
    FRAME_TYPE_PROC_AUXV,     // /proc/<pid>/auxv

    // keep append
    FRAME_TYPE_MAX
};
static_assert(FRAME_TYPE_MAX < FRAME_TYPE_SIZE, "type oversize");

/* Frame Header
 */
#pragma pack(push, 1)
struct FrameHeader {
    uint8_t type:FRAME_TYPE_BITS;
};
#pragma pack(pop)
static_assert(sizeof(FrameHeader) == 1, "");

/* structurt or small data was wrapped by frames.
 * echo frame has a header tell reader what the data is.
 */
struct Frame {
    FrameHeader f_hdr;
    char data;
public:
    Frame();
};

/* Lz4 stream support.
 */
class Lz4Stream {
public:

// defines the buffers in ring
#define MAX_RING_BUF 2

    enum lz4_mode {
        LZ4_Compress,
        LZ4_Decompress
    };

    Lz4Stream(lz4_mode mode);
    ~Lz4Stream();
    
    // write bytes 
    int SetBlock(BlockType t);
    int Flush();
    int Write(const char* s, size_t n);
    int WriteBlock(const char* s, size_t n, BlockType t);
    //int WriteFrame(FrameType t, const char* s, size_t n);
    int WriteRaw(const char* s, size_t n);

    // read bytes
    Block* ReadBlock(BlockHeader& out_hdr);
    int ReadRaw(char* out, size_t n);
    int Peek(char*out, size_t n);

    // put or get file to stream 
    ProcFile* GetFile();
    int PutFile(ProcFile *pf);

    // file position
    long Tell();
    int Seek(long offset);

    // open file and create stream
    int Open(const char *file);   
    // close file
    void Close();

    void PrintStat();

private:
    Block& CurrentBlock() {
        return _blocks[_block_index % MAX_RING_BUF];
    }
   
    bool isCompressor() {
        return _enc != NULL;
    }

    bool isDecompressor() {
        return _dec != NULL;
    }

    // Compress a block to file
    int Compress(Block& block, BlockHeader& hdr);

    // Decompress a block from file
    int Decompress(Block& block);

private:
    Block _blocks[MAX_RING_BUF];    // lz4 uses double blocks.
    size_t _block_index;            // indicate the block current choose.
    BlockType _block_type;                // saved current block type

    FILE *_file;                    // holds the file stream.
    lz4_mode _mode;
    LZ4_stream_t *_enc;             // lz4 compresser.
    LZ4_streamDecode_t *_dec;       // lz4 decompresser.

    // counter
    size_t _size_real;          // real bytes, decompressed data size.
    size_t _size_file;          // file bytes, compressed data size.
};

};

#endif // _ARTHUR_LZ4_H_
