# sharpen

```
sharpen/<radius>x<sigma>
```

Sharpens the image with a Gaussian operator. `radius` is the area each pixel is
compared against, and `sigma` is the strength. A radius of 0 lets ImageMagick
pick one from the sigma, which is what to use.

```
sharpen/0x1.5
sharpen/0x0.8      subtler
```

Without a sigma, 1.0 is used.
