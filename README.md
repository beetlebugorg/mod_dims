mod-dims
========

mod-dims is an HTTP microservice for dynamic image manipulation. It run as an Apache httpd module.

Dependencies
------------

* Apache 2.4.x
* Imagemagick 7.1.x
* libcurl 7.x

Compiling
---------

```bash
$ zig build 
find zig-out/
zig-out/
zig-out/lib
zig-out/lib/libmod_dims.so.4
zig-out/lib/libmod_dims.so.4.0.0
zig-out/lib/libmod_dims.so
```

Installation
------------

Add the following to the Apache configuration:

```
    <IfModule !mod_dims.c>
        LoadModule dims_module modules/mod_dims.so
    </IfModule>

    AddHandler dims-local .gif .jpg

    <Location /dims3/>
        SetHandler dims3
    </Location>

    <Location /dims4/>
        SetHandler dims3
    </Location>

    <Location /dims-status/>
        SetHandler dims-status
    </Location>
```

This assumes mod_dims.so has been installed in $HTTP_ROOT/modules.

Errors
======

There are three classes of errors in mod_dims; 

- Errors caused during downloading of a source image.  These
  come directly from libcurl and are logged as-is.

- Errors caused during an ImageMagick operation.  These come
  directly from ImageMagik and are logged as-is.

- Errors caused during processing of a request by mod_dims.  These
  fall into the category of bad input checking, bad config, etc.

ImageMagick Timeout Error Format:
---------------------------------

[client <client ip address> Imagemagick operation, '<operation>', timed out after 4 ms

<operation> would be something like "Resize/Image" or "Save/Image".

General Error Format:
---------------------

Errors will be in the following format in Apache's error log:

[client <client ip address>] <source> error, '<source error message>', on request: <request uri>

For example:

[client 10.181.182.244] Imagemagick error, 'no decode delegate for this image
format `'', on request: /20080803WI55426251_WI.jpg/TEST/thumbnail/78x100/

Common libcurl Error Messages:
------------------------------

These message are usually self explanatory so no explain is provided.  The 
URL that failed will be logged along with this message.

* Couldn't connect to server
* Couldn't resolve DNS
* Timeout was reached

Common mod_dims Error Messages:
--------------------------------

* Requested URL has hostname that is not in the whitelist. (aaolcdn.com)
* Application ID is not valid
* Parsing thumbnail geometry failed
* Parsing crop geometry failed
* Failed to read image
    This occurs if ImageMagick had trouble reading the image.
* Unable to stat image file
    This occurs when a local request is unable to find the image to resize.

Common ImageMagick Error Messages:
---------------------------------

* Memory allocation failed
    This should rarely occur, if ever, but usually when it does it's the result
    of an ImageMagick timeout.

* unrecognized image format
* no decode delegate for this image format
>    This happens when ImageMagick doesn't no how to read a source image.

* zero-length blob not permitted
>    This may occur if there was a failure to download the source image.

* Unsupported marker type 0x03
    This may occur if the image is corrupted.  The "0x03" may be different
    depending on the corruption.

Other more serious errors:
--------------------------

Any errors that have "Assertion failed" are results of bugs in the code and
can be considered serious.

- Assertion failed: (wand->signature == WandSignature), 
  function MagickGetImageFormat, file wand/magick-image.c, line 4137.


