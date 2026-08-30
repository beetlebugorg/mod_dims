# crop

```
crop/<width>x<height>+<x>+<y>
```

Cuts a region out of the image. The offset is measured from the top left.

```
crop/100x100+10+20     100 by 100, starting 10 across and 20 down
crop/100x100           100 by 100 from the centre
crop/50%x50%+0+0       the top left quarter
```

A region larger than the image is reduced to fit, so a crop that overhangs an
edge keeps the part that is on the image.

A region that lies entirely off the image is refused with `400`. An offset of
exactly the width or the height leaves nothing, so it is refused the same way.
The offset one pixel inside the edge keeps a strip one pixel wide.

Some clients escape a `+` as `%20`, which arrives as a space. `crop` converts a
space back to a `+`, so `100x100%20350%200` works.
