/**
 * @file    CryIf_Cbk.h
 * @brief   Callback interface of the CryIf called by the Crypto Driver.
 */
#ifndef CRYIF_CBK_H
#define CRYIF_CBK_H

#include "Crypto_GeneralTypes.h"

void CryIf_CallbackNotification(Crypto_JobType *job, Std_ReturnType result);

#endif
