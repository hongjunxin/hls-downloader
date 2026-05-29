## HLS STREAM DOWNLOADER

FFmpeg tool can download hls stream and convert it to specified format video. But it download ts files one by one. *dhls* use epoll to download ts files concurrently, and then use ffmpeg to merge ts files into a specified format output video.

## usage
```
$ ./dhls -i http://example.com/xxx/index.m3u8 -o sample.mp4
$ ./dhls -i http://example.com/xxx/index.m3u8 -o sample.mp4 -H 'Referer: https://example.com' -H 'Cookie: foo=bar'
```

option
- -i [input url]
- -o [output file name], include format
- -l [error | warn | info | debug], debug level (default error)
- -c [fd number], specified the number of fd to download ts files (default 20). It doesn't mean fd number is the higher the better.
- -H [header], append request header, can be specified multiple times. Example: `-H 'Referer: https://example.com'`

## thirdparty
- libcurl
- openssl
- ffmpeg tool
- ffmpeg libav

## test
```
file size ｜  net speed  ｜ download time ｜
  367MB   ｜  20Mbps     ｜   12.995s     ｜
```

## license
- MIT
