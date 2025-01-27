#ifndef MSUBIMAGE_H
#define MSUBIMAGE_H

#include <fitsio.h>

#define EQUM   0
#define GALM   1
#define PIX    2
#define HDU    3
#define SHRINK 4

struct mSubimageParams
{
   int ibegin;          /* column offset */
   int iend;            /* last column */
   int jbegin;          /* row offset */
   int jend;            /* last row */
   long nelements;      /* row length */
   int nfound;
   int isDSS;
   double crpix[10];
   double cnpix[10];
   long naxis;
   long naxes[10];
};


/****************************************/
/* Define mSubimage function prototypes */
/****************************************/

void              mSubimage_fixxy          (double *x, double *y, int *offscl);
struct WorldCoor *mSubimage_getFileInfo    (fitsfile *infptr, char **header, struct mSubimageParams *params);
int               mSubimage_copyHeaderInfo (fitsfile *infptr, fitsfile *outfptr, struct mSubimageParams *params);
int               mSubimage_copyData       (fitsfile *infptr, fitsfile *outfptr, struct mSubimageParams *params);
int               mSubimage_dataRange      (fitsfile *infptr, int *imin, int *imax, int *jmin, int *jmax);
void              mSubimage_printFitsError (int);

#endif
