Dependencies
============

* Apache 2.4+
* Imagemagick 6.9+ or 7.x (Docker/devcontainer pins 7.1.2-13)
* libcurl 8+

Testing
=======

Run config-level checks:

    ./tests/config-smoke.sh

Run end-to-end hardening integration tests (requires Docker, Python 3, OpenSSL, curl):

    ./tests/hardening-integration.sh

Compiling
=========

./autorun.sh --with-imagemagick=/path/to/imagemagick --with-apache=/path/to/apache

The paths provided above are prefix paths used to install those dependencies. If you installed
Imagemagick and Apache (including APR) in /usr/local you would run:

./autorun.sh --with-imagemagick=/usr/local --with-apache=/usr/local

Installation
============

Add the following to the Apache configuration:

    <IfModule !mod_dims.c>
        LoadModule dims_module modules/mod_dims.so
    </IfModule>

    AddHandler dims-local .gif .jpg

    <Location /dims/>
        SetHandler dims
    </Location>

    <Location /dims3/>
        SetHandler dims3
    </Location>

    <Location /dims-status/>
        SetHandler dims-status
    </Location>

    # Optional hardening.
    # DimsSignatureAlgorithm hmac-sha256
    # DimsStrictValidation true
    # DimsAllowedFetchSchemes http,https
    # DimsMaxDownloadBytes 67108864
    # DimsMaxRedirects 5
    # DimsConnectTimeout 1000
    # DimsLogSensitiveData false
    # DimsEncryptionAlgorithm AES/GCM/NoPadding
    # DimsAllowLegacyEcb false

This assumes mod_dims.so has been installed in $HTTP_ROOT/modules.

Security Modes
==============

`/dims4/` supports two signature algorithms:

* `legacy-md5` (default for backward compatibility)
* `hmac-sha256` (recommended for new integrations)

To enforce stronger validation and full-length signatures, enable:

    DimsStrictValidation true

Remote Fetch Hardening
======================

Recommended defaults for safer upstream fetch behavior:

    DimsAllowedFetchSchemes http,https
    DimsMaxDownloadBytes 67108864
    DimsMaxRedirects 5
    DimsConnectTimeout 1000
    DimsLogSensitiveData false

Encrypted `eurl` recommendations:

    DimsEncryptionAlgorithm AES/GCM/NoPadding
    DimsAllowLegacyEcb false

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
