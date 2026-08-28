# rotate

```
rotate/<degrees>
```

Turns the image clockwise. Any number of degrees works, not only multiples of
90.

```
rotate/90
rotate/180
rotate/45
```

An angle that is not a multiple of 90 makes the image larger, because the
corners need somewhere to go. The added area is transparent, or white in a
format without an alpha channel.
