# Apache `mod_dims`

An on-demand image filtering modules for Apache.

Will read local images, or proxy images from another server and apply transforms, convert formats and apply compression.

Uses Imagemagick.

## Dependencies

 * Apache 2.2.x
 * Imagemagick 6.6+
 * libcurl 7.18.0+

On Ubuntu or Debian, this should do the job:

```
apt install apache2-dev libmagickwand-dev libmagick++-dev libmagickcore-dev libcurl4-gnutls-dev libtool build-essential automake
```

## Install

```
./autorun.sh --with-imagemagick=/path/to/imagemagick --with-apache=/path/to/apache
```

The paths provided above are prefix paths used to install those dependencies. If you installed
Imagemagick and Apache (including APR) in /usr/local you would run:

```
./autorun.sh --with-imagemagick=/usr/ --with-apache=/usr/
make
make install # probably want to sudo this
```

** Assumiung installation into `/usr/`**

Load the module in `/etc/apache2/mods-available/dims.load

```
LoadModule dims_module /usr/lib/apache2/modules/mod_dims.so
```

Symlink to enable

```
ln -s /etc/apache2/mods-available/dims.load apache2/mods-enabled/dims.load
```

Restart apache.

### Example usage

In your vhost:

```
    AddHandler dims-local .gif .jpg

    <Location /dims/>
        SetHandler dims
    </Location>

    <Location /dims-status/>
        SetHandler dims-status
    </Location>

    <Location /dims3/>
        SetHandler dims3
    </Location>


    DimsDefaultImageURL http://images.example.com/404.jpg
    DimsAddClient mydims http://images.example.com/404.jpg 86400
    DimsAddWhiteList images.example.com
    DimsImageMagickTimeout 5000
    DimsDownloadTimeout 5000

    <Location /dims-status/>
        SetHandler dims-status
    </Location>

    <Location /dims-sizer/>
        SetHandler dims-sizer
    </Location>

```

### Example requests

Thumbnail an image (resize and crop): `http://my.dims.server/dims3/mydims/thumbnail/100x100/http://images.example.com/image.jpg`

Resize an image and flip it: `http://my.dims.server/dims3/mydims/resize/100x100/flip/true/http://images.example.com/image.jpg`

Get image dimensions: `http://my.dims.server/dims-sizer/http://images.example.com/image.jpg` ->

```
{
	"height": 661,
	"width": 990
}
```

## Available filters

### Modulate

```
modulate/<brightness>,<saturation>,<hue>
```

  * brightness: 0 (black) - 100 (normal) - 9999 (completely bleached out)
  * saturation: 0 (grey) - 100 (normal) - 9999 (aliens)
  * hue: 0 (shift colour wheel left 180 deg) - 100 (normal) - 200 (shift right 180 deg)

### Normalise

Equalises the curves for a cheap 'punchy' effect.

```
normalize
```

### Mirrored Floor

Flips the image and renders it below the original. Useful for making quick and dirty background images or repeaters.

```
mirroredfloor
```

### Flip

Flips an imagea. (Upside down)

```
flip
```

### Flop

Flops an image. (Left to right)

```
flop
```

<!-- ### Liquid Resize

Resize that attempts to preserve features by using seam carving.  Very fun!  Does not honour aspect ratio (by design).

```
liquidresize/<width>x<height>
```

-->

### Resize

Resize that honours aspect ratio of original so that image is *no larger* than new width x height.

```
resize/<width>x<height>
```

### Sharpen

```
sharpen/<radius>,<sigma>
```

  * radius: 0- (pixels, controls size of convolution)
  * sigma: 0- (pixels, controls rolloff of gaussian used, typically sqrt(radius) for normal usage, e.g. `sharpen/4,2`)

### Thumbnail

Fast resample for small thumbnails which also crops to exactly requested size.

```
thumbnail/<width>x<height>
```

### Crop

```
crop/<width>x<height>+<x>+<y>
```

### Format

```
format/<jpg|png|gif>
```

### Quality 

```
quality/<factor>
```

  * quality: 1-100 (only affects JPG output)

### Blur

```
blur/<radius>,<sigma>
```

  * radius: 0- (pixels, controls size of convolution)
  * sigma: 0- (pixels, controls rolloff of gaussian used, typically sqrt(radius) for normal usage, e.g. `blur/9,3`.  sigma > radius gives interesting effects)

### Brightness

```
brightness/<brightness>,<contrast>
```

  * brightness: -100 - 100
  * contrast: -100 - 100

### FlipFlop

```
flipflop/<axis>
```

  * axis: horizontal | vertical

### Sepia

```
sepia/<threshold>
```

  * threshold: 0-100

### Greyscale (grayscale)

(Faster than desaturate)

```
grayscale/<true|false>
```

### Autolevel

```
autolevel/<true|false>
```

### Invert

```
invert/<true|false>
```

### Rotate

```
rotate/<angle>
```

  * angle: 0-359

## Errors

There are three classes of errors in `mod_dims`: 

  - Errors caused during downloading of a source image. These come directly from libcurl and are logged as-is.

  - Errors caused during an ImageMagick operation. These come directly from ImageMagik and are logged as-is.

  - Errors caused during processing of a request by `mod_dims`. These fall into the category of bad input checking, bad config, etc.

### ImageMagick Timeout Error Format:

```
[client <client ip address> Imagemagick operation, '<operation>', timed out after 4 ms
```

`<operation>` would be something like "Resize/Image" or "Save/Image".

### General Error Format:

Errors will be in the following format in Apache's error log:

```
[client <client ip address>] <source> error, '<source error message>', on request: <request uri>
```

For example:

```
[client 10.181.182.244] Imagemagick error, 'no decode delegate for this image
format `'', on request: /20080803WI55426251_WI.jpg/TEST/thumbnail/78x100/
```

### Common libcurl Error Messages:

These message are usually self explanatory so no explain is provided.  The 
URL that failed will be logged along with this message.

 * Couldn't connect to server
 * Couldn't resolve DNS
 * Timeout was reached

### Common `mod_dims` Error Messages:

 * Requested URL has hostname that is not in the whitelist. (aaolcdn.com)
 * Application ID is not valid
 * Parsing thumbnail geometry failed
 * Parsing crop geometry failed
 * Failed to read image. This occurs if ImageMagick had trouble reading the image.
 * Unable to stat image file. This occurs when a local request is unable to find the image to resize.

### Common ImageMagick Error Messages:

 * Memory allocation failed. This should rarely occur, if ever, but usually when it does it's the result of an ImageMagick timeout.
 * unrecognized image format
 * no decode delegate for this image format. This happens when ImageMagick doesn't no how to read a source image.
 * zero-length blob not permitted. This may occur if there was a failure to download the source image.
 * Unsupported marker type 0x03. This may occur if the image is corrupted.  The "0x03" may be different depending on the corruption.

### Other more serious errors:

Any errors that have "Assertion failed" are results of bugs in the code and
can be considered serious.

```
Assertion failed: (wand->signature == WandSignature), function MagickGetImageFormat, file wand/magick-image.c, line 4137.  
```

