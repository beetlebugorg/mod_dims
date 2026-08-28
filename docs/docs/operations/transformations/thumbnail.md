# thumbnail

```
thumbnail/<geometry>
```

Scales the image to cover the geometry, then crops the overflow from the
centre. The result is exactly the size asked for.

```
thumbnail/100x100      exactly 100 by 100
thumbnail/100          width 100, height follows
```

`resize` fits the image inside the box and leaves it smaller in one dimension.
`thumbnail` fills the box.

Metadata is stripped, including any orientation tag, because the image has
already been oriented.
