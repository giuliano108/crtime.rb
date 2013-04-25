# Given a device and a file, returns the file creation time (crtime).
# Works only on ext4 filesystem with 256 bytes inodes.
# Requires libext2fs (apt-get install e2fslibs) and root access.
# See:
#      http://www.108.bz/posts/it/file-creation-time-on-linux/
#      http://computer-forensics.sans.org/blog/2011/03/14/digital-forensics-understanding-ext4-part-2-timestamps
# -- giuliano@108.bz

require 'rubygems'
require 'ffi'

module Ext2Fs

    # See: /usr/include/ext2fs/ext2fs.h

    extend FFI::Library
    ffi_lib '/lib/x86_64-linux-gnu/libext2fs.so.2'

    EXT2_FLAG_SOFTSUPP_FEATURES = 0x8000
    EXT2_FLAG_64BITS            = 0x20000
    EXT2_NDIR_BLOCKS            = 12
    EXT2_IND_BLOCK              = EXT2_NDIR_BLOCKS
    EXT2_DIND_BLOCK             = (EXT2_IND_BLOCK + 1)
    EXT2_TIND_BLOCK             = (EXT2_DIND_BLOCK + 1)
    EXT2_N_BLOCKS               = (EXT2_TIND_BLOCK + 1)

    typedef :long,    :errcode_t
    typedef :pointer, :io_manager
    typedef :pointer, :ext2_filsys
    typedef :pointer, :ext2_filsys_ptr
    typedef :pointer, :ext2_inode
    typedef :pointer, :struct_ext2_inode_ptr
    typedef :uint32,  :ext2_ino_t

    attach_variable :unix_io_manager, :unix_io_manager, :pointer;

    # Top portion of struct_ext2_filsys
    class Ext2FilsysAbridged < FFI::Struct
        layout :magic,       :errcode_t,
               :io,          :pointer,
               :flags,       :int,
               :device_name, :string,
               :super,       :pointer,
               :blocksize,   :uint
    end

    class Ext2InodeLarge_linux1 < FFI::Struct
        layout :l_i_version, :uint32
    end
    class Ext2InodeLarge_hurd1 < FFI::Struct
        layout :h_i_translator, :uint32
    end
    class Ext2InodeLarge_osd1 < FFI::Union
        layout :linux1, Ext2InodeLarge_linux1,
               :hurd1,  Ext2InodeLarge_hurd1
    end

    class Ext2InodeLarge_linux2 < FFI::Struct
        layout :l_i_blocks_hi,     :uint16,
               :l_i_file_acl_high, :uint16,
               :l_i_uid_high,      :uint16,
               :l_i_gid_high,      :uint16,
               :l_i_checksum_lo,   :uint16,
               :l_i_reserved,      :uint16
    end
    class Ext2InodeLarge_hurd2 < FFI::Struct
        layout :h_i_frag,      :uint8,
               :h_i_fsize,     :uint8,
               :h_i_mode_high, :uint16,
               :h_i_uid_high,  :uint16,
               :h_i_gid_high,  :uint16,
               :h_i_author,    :uint32
    end
    class Ext2InodeLarge_osd2 < FFI::Union
        layout :linux2, Ext2InodeLarge_linux2,
               :hurd2,  Ext2InodeLarge_hurd2
    end

    class Ext2InodeLarge < FFI::Struct
        layout :i_mode,         :uint16,
               :i_uid,          :uint16,
               :i_size,         :uint32,
               :i_atime,        :uint32,
               :i_ctime,        :uint32,
               :i_mtime,        :uint32,
               :i_dtime,        :uint32,
               :i_gid,          :uint16,
               :i_links_count,  :uint16,
               :i_blocks,       :uint32,
               :i_flags,        :uint32,
               :osd1,           Ext2InodeLarge_osd1,
               :i_block,        [:uint32, EXT2_N_BLOCKS],
               :i_generation,   :uint32,
               :i_file_acl,     :uint32,
               :i_size_high,    :uint32,
               :i_fadd,         :uint32,
               :osd2,           Ext2InodeLarge_osd2,
               :i_extra_isize,  :uint16,
               :i_checksum_hi,  :uint16,
               :i_ctime_extra,  :uint32,
               :i_mtime_extra,  :uint32,
               :i_atime_extra,  :uint32,
               :i_crtime,       :uint32,
               :i_crtime_extra, :uint32,
               :i_version_hi,   :uint32
    end

    # extern errcode_t ext2fs_open(const char *name, int flags, int superblock,
    #                unsigned int block_size, io_manager manager,
    #                ext2_filsys *ret_fs);
    attach_function :ext2fs_open, [:string, :int, :int, :uint, :io_manager, :ext2_filsys_ptr], :errcode_t

    # extern errcode_t ext2fs_read_inode_full(ext2_filsys fs, ext2_ino_t ino,
    #                   struct ext2_inode * inode,
    #                   int bufsize);
    attach_function :ext2fs_read_inode_full, [:ext2_filsys, :ext2_ino_t, :struct_ext2_inode_ptr, :int], :errcode_t

end

if !(ARGV.length == 2 && File.readable?(ARGV[0]) && File.readable?(ARGV[1]))
    puts <<-EOM
    Usage: $0 device_with_ext4_filesystem filename
      Make sure the device and the file are readable
    EOM
    exit
else
    device   = ARGV[0]
    filename = ARGV[1]
end

current_fs_ptr = FFI::MemoryPointer.new :pointer
rc = Ext2Fs.ext2fs_open device,
                        Ext2Fs::EXT2_FLAG_SOFTSUPP_FEATURES | Ext2Fs::EXT2_FLAG_64BITS,
                        0, 0,
                        Ext2Fs.unix_io_manager, current_fs_ptr
fail "Error #{rc} on ext2fs_open" if rc != 0
current_fs = Ext2Fs::Ext2FilsysAbridged.new current_fs_ptr.read_pointer

# This is quite fragile, I should also check s_rev_level in struct ext2_super_block
INODE_SIZE_OFFSET=13*2+6+4*2+2+1*2
inode_size = current_fs[:super].read_array_of_uint16(INODE_SIZE_OFFSET+1)[INODE_SIZE_OFFSET]
fail "inode size is not 256 bytes" if inode_size != 256

inode_buf_ptr = FFI::MemoryPointer.new :char, inode_size
inode_number = File.stat(filename).ino
rc = Ext2Fs.ext2fs_read_inode_full current_fs.pointer, inode_number, inode_buf_ptr, inode_size
fail "Error #{rc} on ext2fs_read_inode_full" if rc != 0
inode = Ext2Fs::Ext2InodeLarge.new inode_buf_ptr

printf "crtime: 0x%08x:%08x -- %s\n", inode[:i_crtime], inode[:i_crtime_extra], Time.at(inode[:i_crtime]).to_s
