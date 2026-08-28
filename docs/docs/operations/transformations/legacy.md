# legacy_thumbnail and legacy_crop

```
legacy_thumbnail/<geometry>
legacy_crop/<geometry>
```

The commands the removed `/dims/` endpoint mapped onto. They crop from the
centre rather than by gravity.

`legacy_crop` crops to the geometry, centred.

`legacy_thumbnail` scales to cover the geometry and then crops the overflow
from the centre, like [`thumbnail`](/operations/transformations/thumbnail) but
without setting the sampling factors a JPEG source gets.

Prefer [`crop`](/operations/transformations/crop) and
[`thumbnail`](/operations/transformations/thumbnail) in a new request. These
two remain so existing URLs keep working.
