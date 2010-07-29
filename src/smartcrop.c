/*
 * Copyright 2009 AOL LLC 
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at 
 *         
 *         http://www.apache.org/licenses/LICENSE-2.0 
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <wand/MagickWand.h>
/*
#define BENCHMARK(op, block) \
    do { \
        struct timeval _begin, _end; \
        gettimeofday(&_begin, NULL); \
        do { block } while(0); \
        gettimeofday(&_end, NULL); \
        fprintf(stdout, op " took %.5f seconds\n\n", _end.tv_sec - _begin.tv_sec + (_end.tv_usec - _begin.tv_usec) / 1000000.0); \
    } while(0)
*/
#define BENCHMARK(op, block) \
    do { block } while(0)
#define ThrowWandException(wand) \
    do { \
        ExceptionType severity; \
        char *description = MagickGetException(wand, &severity); \
        fprintf(stderr, "%s %s %lu %s\n", GetMagickModule(), description); \
        MagickRelinquishMemory(description); \
        exit(0); \
    } while(0)
static void rgb2hsv(double red, double green, double blue, double *hue, double *saturation, double *value) {
    double min = red < green && red < blue ? red : green < red && green < blue ? green : blue;
    double max = red > green && red > blue ? red : green > red && green > blue ? green : blue;
    double delta = max - min;
    *value = (double)max / 255.0;
    if(max == 0 || max == min) {
        *saturation = 0.0;
        *hue = 0.0;
    } else {
        *saturation = delta / (double)max;
        if(red == max) {
            *hue = 60.0 * (green - blue) / delta;
        } else if(green == max) {
            *hue = 120.0 + 60.0 * (blue - red) / delta;
        } else {
            *hue = 240.0 + 60.0 * (red - green) / delta;
        }
        if(*hue < 0.0) {
            *hue += 360.0;
        }
    }
}
void smartCrop(MagickWand *wand, int resolution, unsigned long cropWidth, unsigned long cropHeight) {
    unsigned long imageWidth = MagickGetImageWidth(wand), imageHeight = MagickGetImageHeight(wand);
    unsigned long resizeWidth = cropWidth, resizeHeight = cropHeight;
    double imageRatio = (double)imageWidth / (double)imageHeight, cropRatio = (double)cropWidth / (double)cropHeight;
    if(imageRatio == cropRatio) {

        /* no need to crop */
        goto resize;
    } else {
        int xIndex, yIndex;
        int xResolution, yResolution;
        unsigned long segmentWidth, segmentHeight;
        double aHue, aSaturation, aValue, bHue, bSaturation, bValue;
        double diffAverage;
        ExceptionInfo exception;
        const PixelPacket *currentPixel, *firstPixel;
        if(imageRatio < cropRatio) {

            /* have to cut top/bottom */
            xResolution = resolution / 2;
            yResolution = resolution * 2;
        } else {

            /* have to cut left/right */
            xResolution = resolution * 2;
            yResolution = resolution / 2;
        }
        {

            /* init */
            double redCounts[yResolution][xResolution];
            double greenCounts[yResolution][xResolution];
            double blueCounts[yResolution][xResolution];
            double xDiffs[yResolution][xResolution - 1];
            double yDiffs[yResolution - 1][xResolution];
            segmentWidth = imageWidth / xResolution;
            segmentHeight = imageHeight / yResolution;
            firstPixel = AcquireImagePixels(GetImageFromMagickWand(wand), 0, 0, imageWidth, imageHeight, &exception);
            for(yIndex = 0; yIndex < yResolution; yIndex ++) {
                for(xIndex = 0; xIndex < xResolution; xIndex ++, currentPixel ++) {
                    redCounts[yIndex][xIndex] = 0.0;
                    blueCounts[yIndex][xIndex] = 0.0;
                    greenCounts[yIndex][xIndex] = 0.0;
                }
            }
            for(yIndex = 0; yIndex < yResolution; yIndex ++) {
                for(xIndex = 0; xIndex < xResolution - 1; xIndex ++) {
                    xDiffs[yIndex][xIndex] = 0.0;
                }
            }
            for(yIndex = 0; yIndex < yResolution - 1; yIndex ++) {
                for(xIndex = 0; xIndex < xResolution; xIndex ++) {
                    yDiffs[yIndex][xIndex] = 0.0;
                }
            }

            /* histogram */
            currentPixel = firstPixel;
            for(yIndex = 0; yIndex < imageHeight; yIndex ++) {
                for(xIndex = 0; xIndex < imageWidth; xIndex ++, currentPixel ++) {
                    redCounts[(yIndex / segmentHeight) % yResolution][(xIndex / segmentWidth) % xResolution] += currentPixel->red;
                    greenCounts[(yIndex / segmentHeight) % yResolution][(xIndex / segmentWidth) % xResolution] += currentPixel->green;
                    blueCounts[(yIndex / segmentHeight) % yResolution][(xIndex / segmentWidth) % xResolution] += currentPixel->blue;
                }
            }

            /* compare all the histograms */
            for(yIndex = 0; yIndex < yResolution; yIndex ++) {
                for(xIndex = 0; xIndex < xResolution - 1; xIndex ++) {

                    /* sum(ai * bi) / (sum(ai * ai) * sum(bi * bi)) */
                    rgb2hsv(
                        redCounts[yIndex][xIndex] / segmentWidth / segmentHeight,
                        blueCounts[yIndex][xIndex] / segmentWidth / segmentHeight,
                        greenCounts[yIndex][xIndex] / segmentWidth / segmentHeight,
                        &aHue, &aSaturation, &aValue
                    );
                    rgb2hsv(
                        redCounts[yIndex][xIndex + 1] / segmentWidth / segmentHeight,
                        blueCounts[yIndex][xIndex + 1] / segmentWidth / segmentHeight,
                        greenCounts[yIndex][xIndex + 1] / segmentWidth / segmentHeight,
                        &bHue, &bSaturation, &bValue
                    );

                    /* simple average of the 3 diffs */
                    xDiffs[yIndex][xIndex] = (aHue == 0.0 && bHue == 0.0 && aSaturation == 0.0 && bSaturation == 0.0 ? 1.0 : (
                        (aHue * bHue + aSaturation * bSaturation) /
                        sqrt(aHue * aHue + aSaturation * aSaturation) /
                        sqrt(bHue * bHue + bSaturation * bSaturation)
                    )) * fabs(aValue - bValue);
                }
            }
            for(yIndex = 0; yIndex < yResolution - 1; yIndex ++) {
                for(xIndex = 0; xIndex < xResolution; xIndex ++) {

                    /* sum(ai * bi) / (sum(ai * ai) * sum(bi * bi)) */
                    rgb2hsv(
                        redCounts[yIndex][xIndex] / segmentWidth / segmentHeight,
                        blueCounts[yIndex][xIndex] / segmentWidth / segmentHeight,
                        greenCounts[yIndex][xIndex] / segmentWidth / segmentHeight,
                        &aHue, &aSaturation, &aValue
                    );
                    rgb2hsv(
                        redCounts[yIndex + 1][xIndex] / segmentWidth / segmentHeight,
                        blueCounts[yIndex + 1][xIndex] / segmentWidth / segmentHeight,
                        greenCounts[yIndex + 1][xIndex] / segmentWidth / segmentHeight,
                        &bHue, &bSaturation, &bValue
                    );

                    /* simple average of the 3 diffs */
                    xDiffs[yIndex][xIndex] = (aHue == 0.0 && bHue == 0.0 && aSaturation == 0.0 && bSaturation == 0.0 ? 1.0 : (
                        (aHue * bHue + aSaturation * bSaturation) /
                        sqrt(aHue * aHue + aSaturation * aSaturation) /
                        sqrt(bHue * bHue + bSaturation * bSaturation)
                    )) * fabs(aValue - bValue);
                }
            }
            {

                /* global diff */
                double diffs[yResolution][xResolution];
                for(yIndex = 0; yIndex < yResolution; yIndex ++) {
                    for(xIndex = 0; xIndex < xResolution; xIndex ++) {
                        if(yIndex == 0) {
                            if(xIndex == 0) {
                                diffs[yIndex][xIndex] = (xDiffs[yIndex][xIndex] + yDiffs[yIndex][xIndex]) / 2;
                            } else if(xIndex == xResolution - 1) {
                                diffs[yIndex][xIndex] = (xDiffs[yIndex][xIndex - 1] + yDiffs[yIndex][xIndex]) / 2;
                            } else {
                                diffs[yIndex][xIndex] = (xDiffs[yIndex][xIndex - 1] + xDiffs[yIndex][xIndex] + yDiffs[yIndex][xIndex]) / 3;
                            }
                        } else if(yIndex == yResolution - 1) {
                            if(xIndex == 0) {
                                diffs[yIndex][xIndex] = (xDiffs[yIndex][xIndex] + yDiffs[yIndex - 1][xIndex]) / 2;
                            } else if(xIndex == xResolution - 1) {
                                diffs[yIndex][xIndex] = (xDiffs[yIndex][xIndex - 1] + yDiffs[yIndex - 1][xIndex]) / 2;
                            } else {
                                diffs[yIndex][xIndex] = (xDiffs[yIndex][xIndex - 1] + xDiffs[yIndex][xIndex] + yDiffs[yIndex - 1][xIndex]) / 3;
                            }
                        } else {
                            if(xIndex == 0) {
                                diffs[yIndex][xIndex] = (xDiffs[yIndex][xIndex] + yDiffs[yIndex - 1][xIndex] + yDiffs[yIndex][xIndex]) / 3;
                            } else if(xIndex == xResolution - 1) {
                                diffs[yIndex][xIndex] = (xDiffs[yIndex][xIndex - 1] + yDiffs[yIndex - 1][xIndex] + yDiffs[yIndex][xIndex]) / 3;
                            } else {
                                diffs[yIndex][xIndex] = (xDiffs[yIndex][xIndex - 1] + xDiffs[yIndex][xIndex] + yDiffs[yIndex - 1][xIndex] + yDiffs[yIndex][xIndex]) / 4;
                            }
                        }
                    }
                }
                diffAverage = 0.0;
                for(yIndex = 0; yIndex < yResolution; yIndex ++) {
                    for(xIndex = 0; xIndex < xResolution; xIndex ++) {
                        diffAverage += diffs[yIndex][xIndex];
                        fprintf(stdout, "%.6f ", diffs[yIndex][xIndex]);
                    }
                    fprintf(stdout, "\n");
                }
                diffAverage /= yResolution * xResolution;
                {

                    /* find crop */
                    int searchX, searchY, boundWidth, boundHeight, boundXIndex, boundYIndex, boundXMin = 0, boundYMin = 0;
                    double boundDiffMin = 0.0;
                    long cropX, cropY;
                    unsigned long cropWidth, cropHeight;
                    if(imageRatio < cropRatio) {
                        cropWidth = imageWidth;
                        cropHeight = (unsigned long)(imageWidth / cropRatio);
                        boundWidth = xResolution;
                        boundHeight = cropHeight / segmentHeight;
                        searchX = 1;
                        searchY = yResolution - boundHeight + 1;
                    } else {
                        cropWidth = (unsigned long)(imageHeight * cropRatio);
                        cropHeight = imageHeight;
                        boundWidth = cropWidth / segmentWidth;
                        boundHeight = yResolution;
                        searchX = xResolution - boundWidth + 1;
                        searchY = 1;
                    }
                    {
                        double bias = 0.1;
                        double boundDiffs[searchY][searchX];
                        for(yIndex = 0; yIndex < searchY; yIndex ++) {
                            for(xIndex = 0; xIndex < searchX; xIndex ++) {
                                boundDiffs[yIndex][xIndex] = 0.0;
                                for(boundYIndex = 0; boundYIndex < boundHeight; boundYIndex ++) {
                                    for(boundXIndex = 0; boundXIndex < boundWidth; boundXIndex ++) {
                                        boundDiffs[yIndex][xIndex] +=
                                            isnan(diffs[yIndex + boundYIndex][xIndex + boundXIndex]) ? 0 :
                                            diffs[yIndex + boundYIndex][xIndex + boundXIndex] > 1 ? 0 :
                                            diffs[yIndex + boundYIndex][xIndex + boundXIndex] < diffAverage ? diffs[yIndex + boundYIndex][xIndex + boundXIndex] / 2 :
                                            diffs[yIndex + boundYIndex][xIndex + boundXIndex];
                                    }
                                }
                                boundDiffs[yIndex][xIndex] /= boundWidth * boundHeight * (1 + bias * yIndex / searchY);
                            }
                        }
                        for(yIndex = 0; yIndex < searchY; yIndex ++) {
                            for(xIndex = 0; xIndex < searchX; xIndex ++) {
                                if((yIndex == 0 && xIndex == 0) || boundDiffs[yIndex][xIndex] > boundDiffMin) {
                                    boundXMin = xIndex;
                                    boundYMin = yIndex;
                                    boundDiffMin = boundDiffs[yIndex][xIndex];
                                }
                            }
                        }
                        cropX = boundXMin * segmentWidth;
                        if(cropX + cropWidth > imageWidth) cropX = imageWidth - cropWidth;
                        cropY = boundYMin * segmentHeight;
                        if(cropY + cropHeight > imageHeight) cropY = imageHeight - cropHeight;

                        /* temp */
                        /*
                        drawing = NewDrawingWand();
                        stroke = NewPixelWand();
                        PixelSetColor(stroke, "red");
                        DrawSetStrokeColor(drawing, stroke);
                        for(xIndex = 0; xIndex < xResolution; xIndex ++) {
                            DrawLine(drawing, xIndex * segmentWidth, 0, xIndex * segmentWidth, yResolution * segmentHeight);
                        }
                        for(yIndex = 0; yIndex < yResolution; yIndex ++) {
                            DrawLine(drawing, 0, yIndex * segmentHeight, xResolution * segmentWidth, yIndex * segmentHeight);
                        }
                        PixelSetColor(stroke, "red");
                        DrawSetStrokeColor(drawing, stroke);
                        DrawSetStrokeWidth(drawing, 10.0);
                        DrawSetFillOpacity(drawing, 0.0);
                        DrawRectangle(drawing, cropX, cropY, cropX + cropWidth, cropY + cropHeight);
                        if(MagickDrawImage(wand, drawing) == MagickFalse) ThrowWandException(wand);
                        DestroyDrawingWand(drawing);
                        */
                        MagickCropImage(wand, cropWidth, cropHeight, cropX, cropY);
                    }
                }
            }
        }
    }
    resize:
        MagickScaleImage(wand, resizeWidth, resizeHeight);
}

/* test app for auto thumbnail */
int main(int argc, char **argv) {
    MagickWand *wand;
    int width, height;

    /* check for args */
    if(argc < 5) {
        fprintf(stdout, "Usage: %s input width height output\n", argv[0]);
        return 0;
    }
    width = atoi(argv[2]);
    height = atoi(argv[3]);
    if(width == 0 || height == 0) {
        fprintf(stderr, "Both width and height must be non-zero!\n");
        return 0;
    }

    /* read from file */
    MagickWandGenesis();
    BENCHMARK("open",
        wand = NewMagickWand();
        if(MagickReadImage(wand, argv[1]) == MagickFalse) ThrowWandException(wand);
    );

    /* */
    BENCHMARK("smartCrop",
        /*
        MagickModulateImage(wand, 100, 0, 100);
        */
        smartCrop(wand, 20, width, height);
        MagickWriteImage(wand, argv[4]);
    );

    /* done */
    wand = DestroyMagickWand(wand);
    MagickWandTerminus();
    return 0;
}
