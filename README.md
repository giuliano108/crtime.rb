crtime.rb
=========

Given a device and a file, returns the file creation time (`crtime`).

Works only on ext4 filesystem with 256 bytes inodes.

Requires `libext2fs` (`apt-get install e2fslibs`) and root access.

See:

* [http://www.108.bz/posts/it/file-creation-time-on-linux/](http://www.108.bz/posts/it/file-creation-time-on-linux/)
* [http://computer-forensics.sans.org/blog/2011/03/14/digital-forensics-understanding-ext4-part-2-timestamps](http://www.108.bz/posts/it/file-creation-time-on-linux/)

-- giuliano@108.bz
