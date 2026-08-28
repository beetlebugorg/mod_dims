# dims-local

Transforms a file on disk rather than one fetched over HTTP.

```apacheconf
AddHandler dims-local .gif .jpg .png
```

The commands come from the path after the file:

```
/images/cat.jpg/resize/100x100/
```

No signature and no allowlist apply, because no fetch happens. Anyone who can
reach the location can ask for any transformation of any file it serves.
