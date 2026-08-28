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

A region larger than the image is reduced to fit. An offset outside the image
produces an empty result.

Some clients escape a `+` as `%20`, which arrives as a space. `crop` converts a
space back to a `+`, so `100x100%20350%200` works.
