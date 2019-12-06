# ollvm-breaker
使用Binary Ninja去除ollvm流程平坦混淆

## 使用
使用IDA打开tests目录下的libvdog.so,运行tests下的fix-libvdog.py反混淆,重新分析程序.
当前修复了vdog五个函数,JNI_OnLoad,crazy::GetPackageName,prevent_attach_one,attach_thread_scn,crazy::CheckDex.

## 效果
混淆代码
```c
jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
  jint v2; // w9
  int v3; // w8
  int v4; // w9
  int i; // w8
  int v6; // w9
  const char *v7; // x0
  int v8; // w8
  bool v9; // zf
  const char *v10; // x0
  int v11; // w8
  crazy *v12; // x0
  _JNIEnv *v13; // x1
  crazy *v14; // x8
  int j; // w9
  unsigned int v16; // w0
  int k; // w8
  crazy *v18; // x0
  int l; // w8
  __int64 v21; // [xsp-FA0h] [xbp-1210h]
  __int64 v22; // [xsp-7D0h] [xbp-A40h]
  __int64 v23; // [xsp-30h] [xbp-2A0h]
  __int64 v24; // [xsp-20h] [xbp-290h]
  char *v25; // [xsp+8h] [xbp-268h]
  void *v26; // [xsp+10h] [xbp-260h]
  jint v27; // [xsp+18h] [xbp-258h]
  jint v28; // [xsp+1Ch] [xbp-254h]
  JavaVM *v29; // [xsp+20h] [xbp-250h]
  char *v30; // [xsp+28h] [xbp-248h]
  char *v31; // [xsp+30h] [xbp-240h]
  crazy::String *v32; // [xsp+38h] [xbp-238h]
  __int64 (__fastcall **v33)(JavaVM *, void *); // [xsp+40h] [xbp-230h]
  const char *v34; // [xsp+48h] [xbp-228h]
  int v35; // [xsp+54h] [xbp-21Ch]
  int v36; // [xsp+58h] [xbp-218h]
  int v37; // [xsp+5Ch] [xbp-214h]
  JavaVM *v38; // [xsp+60h] [xbp-210h]
  char *v39; // [xsp+68h] [xbp-208h]
  const char *v40; // [xsp+70h] [xbp-200h]
  int v41; // [xsp+7Ch] [xbp-1F4h]
  char *v42; // [xsp+80h] [xbp-1F0h]
  FILE *v43; // [xsp+88h] [xbp-1E8h]
  int v44; // [xsp+94h] [xbp-1DCh]
  crazy *v45; // [xsp+98h] [xbp-1D8h]
  JavaVM *v46; // [xsp+A0h] [xbp-1D0h]
  int v47; // [xsp+A8h] [xbp-1C8h]
  int v48; // [xsp+ACh] [xbp-1C4h]
  crazy *v49; // [xsp+B0h] [xbp-1C0h]
  JavaVM *v50; // [xsp+B8h] [xbp-1B8h]
  crazy *v51; // [xsp+C0h] [xbp-1B0h]
  crazy *v52; // [xsp+C8h] [xbp-1A8h]
  jint (**v53)(JavaVM *, void **, jint); // [xsp+D0h] [xbp-1A0h]
  crazy::String **v54; // [xsp+E8h] [xbp-188h]
  const char *v55; // [xsp+F0h] [xbp-180h]
  char *v56; // [xsp+F8h] [xbp-178h]
  int v57; // [xsp+104h] [xbp-16Ch]
  const char *v58; // [xsp+108h] [xbp-168h]
  JavaVM *v59; // [xsp+110h] [xbp-160h]
  crazy::String *v60; // [xsp+118h] [xbp-158h]
  __int64 v61; // [xsp+218h] [xbp-58h]

  v26 = reserved;
  v29 = vm;
  v61 = *(_QWORD *)off_DFF90;
  v3 = 1718907589;
  v27 = v2;
LABEL_2:
  v28 = v2;
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          while ( 1 )
          {
            v4 = v3;
            if ( v3 > -1796611739 )
              break;
            v3 = -1591680163;
          }
          if ( v3 > 2122517887 )
            crazy::AbortProcess((crazy *)vm);
          if ( v3 <= 2071858715 )
            break;
          vm = (JavaVM *)strstr(v40, "sg.bigo.enterprise.live:service");
          v50 = vm;
          v3 = -1796611738;
        }
        if ( v3 > 2038211856 )
          crazy::AbortProcess((crazy *)vm);
        if ( v3 <= 1985452749 )
          break;
        v52 = 0LL;
        for ( i = -641593896; ; i = 1602492537 )
        {
          do
          {
            while ( 1 )
            {
              while ( 1 )
              {
                v6 = i;
                if ( i > -959375403 )
                  break;
                v53 = &(*v59)->GetEnv;
                i = 1919464359;
              }
              i = -959375402;
              if ( v6 > -641593897 )
                break;
              if ( v6 != -959375402 )
              {
                while ( 1 )
                  ;
              }
              v59 = v29;
              i = -1329367337;
            }
          }
          while ( v6 == -641593896 );
          if ( v6 != 1919464359 )
            break;
          v60 = (crazy::String *)*v53;
        }
        vm = (JavaVM *)((__int64 (__fastcall *)(JavaVM *, crazy **, __int64))v60)(v29, &v52, 65540LL);
        if ( (_DWORD)vm )
          v3 = 152851513;
        else
          v3 = -225316631;
      }
      if ( v3 <= 1919761782 )
        break;
      v3 = -1591680163;
    }
    if ( v3 > 1873022920 )
      return v28;
    if ( v3 > 1838028940 )
    {
      if ( v35 )
        v3 = 2122517888;
      else
        v3 = 484421971;
    }
    else if ( v3 > 1734873926 )
    {
      vm = (JavaVM *)j_aop_init();
      v3 = -930274867;
    }
    else if ( v3 > 1718907588 )
    {
      v30 = (char *)&v22;
      v31 = (char *)&v21;
      v3 = -7854534;
    }
    else if ( v3 > 1609266205 )
    {
      vm = (JavaVM *)sub_F688();
      v48 = (int)vm;
      v3 = -319607287;
    }
    else if ( v3 > 1465118877 )
    {
      v27 = -1;
      v3 = -1719305536;
    }
    else if ( v3 > 1433580932 )
    {
      if ( v43 )
        v3 = 300194280;
      else
        v3 = 1919761783;
    }
    else if ( v3 > 1297281499 )
    {
      *off_DFF18 = 23;
      v3 = -455933748;
    }
    else if ( v3 > 1182817588 )
    {
      if ( v41 == 15 )
        v3 = 1734873927;
      else
        v3 = -930274867;
    }
    else if ( v3 > -1782315967 )
    {
      if ( v3 > 1038839700 )
      {
        vm = (JavaVM *)strcmp(v34, (const char *)v38);
        v35 = (int)vm;
        v3 = 1838028941;
      }
      else if ( v3 > 1027871973 )
      {
        vm = (JavaVM *)sub_76F60(v51);
        if ( (unsigned __int8)vm & 1 )
          v3 = -1618151004;
        else
          v3 = -990688990;
      }
      else if ( v3 > 939162912 )
      {
        vm = (JavaVM *)crazy::GetPackageName((crazy *)vm);
        v3 = -1039152186;
      }
      else if ( v3 > 775964469 )
      {
        *off_DFEE8 = 1;
        v3 = -376454767;
      }
      else if ( v3 > 742678025 )
      {
        if ( v37 )
          v3 = -625239653;
        else
          v3 = -1665109333;
      }
      else if ( v3 > 585706880 )
      {
        vm = (JavaVM *)crazy::checkdex_1(v49, (_JNIEnv *)reserved);
        if ( (unsigned __int8)vm & 1 )
          v3 = -208592878;
        else
          v3 = 2038211857;
      }
      else if ( v3 > 542546871 )
      {
        v3 = 1985452750;
      }
      else if ( v3 > 492398670 )
      {
        v7 = (const char *)crazy::GetPlatformVersion(v45, (_JNIEnv *)reserved);
        vm = (JavaVM *)strchr(v7, 77);
        if ( vm )
          v3 = 1297281500;
        else
          v3 = -455933748;
      }
      else if ( v3 > 484421970 )
      {
        crazy::String::~String(v32);
        v3 = -1237920250;
      }
      else if ( v3 > 411468606 )
      {
        vm = (JavaVM *)crazy::checkSignature_1(v52, (_JNIEnv *)reserved);
        if ( (unsigned __int8)vm & 1 )
          v3 = -847794275;
        else
          v3 = -648924866;
      }
      else if ( v3 > 300194279 )
      {
        v39 = v31;
        vm = (JavaVM *)memset(v31, 0, 0x7D0u);
        v3 = -1781762611;
      }
      else if ( v3 > 152851512 )
      {
        v8 = 152851513;
LABEL_122:
        v9 = v4 == v8;
        v3 = v4;
        if ( v9 )
        {
          v28 = -1;
          v3 = 1873022921;
        }
      }
      else if ( v3 > 117134184 )
      {
        vm = (JavaVM *)anti_debug_start();
        v3 = -1974907953;
      }
      else if ( v3 > 105840861 )
      {
        v3 = 939162913;
      }
      else if ( v3 > 79862069 )
      {
        vm = (JavaVM *)sub_2E998();
        v38 = vm;
        if ( *(_BYTE *)vm )
          v3 = 105840862;
        else
          v3 = -1237920250;
      }
      else if ( v3 > -7854535 )
      {
        v32 = (crazy::String *)&v24;
        v33 = (__int64 (__fastcall **)(JavaVM *, void *))&v23;
        v3 = -1413870337;
      }
      else if ( v3 > -139557228 )
      {
        v10 = (const char *)sub_2E728();
        vm = (JavaVM *)strlen(v10);
        v46 = vm;
        v3 = -554839129;
      }
      else if ( v3 > -208592879 )
      {
        vm = (JavaVM *)sub_E7EC(*off_DFE98[0], "JNI_OnLoad", v33);
        v37 = (int)vm;
        v3 = 742678026;
      }
      else if ( v3 > -225316632 )
      {
        v11 = 1488047907;
        while ( v11 > -588102432 )
        {
          if ( v11 > 939763251 )
          {
            if ( v11 == 939763252 )
            {
              v59 = *(JavaVM **)v58;
              v11 = 1689158789;
            }
            else if ( v11 == 1689158789 )
            {
              v53 = (jint (**)(JavaVM *, void **, jint))(v59 + 219);
              v11 = -588102431;
            }
            else
            {
              v58 = (const char *)v52;
              v11 = 939763252;
            }
          }
          else
          {
            v60 = (crazy::String *)*v53;
            v11 = -1117867482;
          }
        }
        ((void (__fastcall *)(crazy *, __int64))v60)(v52, off_DFF58);
        v12 = v52;
        *off_DFFF8 = (__int64)v52;
        vm = (JavaVM *)crazy::GetApiLevel(v12, v13);
        v14 = v52;
        *off_DFF18 = (_DWORD)vm;
        v45 = v14;
        v3 = 492398671;
      }
      else if ( v3 > -319607288 )
      {
        if ( v48 )
          v3 = -1781655590;
        else
          v3 = 1465118878;
      }
      else if ( v3 > -376454768 )
      {
        vm = (JavaVM *)sub_2E738();
        v47 = (int)vm;
        v3 = -647280407;
      }
      else if ( v3 > -455933749 )
      {
        v36 = *off_DFF18;
        v3 = -711396653;
      }
      else if ( v3 > -554839130 )
      {
        if ( v46 )
          v3 = -1679856594;
        else
          v3 = -853626539;
      }
      else if ( v3 > -625239654 )
      {
        vm = (JavaVM *)(*v33)(v29, v26);
        v3 = -1782315966;
      }
      else if ( v3 > -647280408 )
      {
        if ( v47 == 2 )
          v3 = -1525365595;
        else
          v3 = -1618151004;
      }
      else
      {
        if ( v3 > -648924867 )
          crazy::AbortProcess((crazy *)vm);
        if ( v3 > -711396654 )
        {
          if ( v36 <= 23 )
            v3 = -376454767;
          else
            v3 = 775964470;
        }
        else if ( v3 > -847794276 )
        {
          v3 = 79862070;
        }
        else if ( v3 > -853626540 )
        {
          v3 = -1719305536;
          v27 = 65540;
        }
        else if ( v3 > -930274868 )
        {
          vm = (JavaVM *)anti_section_hook();
          v3 = 411468607;
        }
        else
        {
          if ( v3 > -990688991 )
          {
            v8 = -990688990;
            goto LABEL_122;
          }
          if ( v3 > -1039152187 )
          {
            for ( j = -1458226292; j == -1458226292; j = -1943834868 )
              v60 = v32;
            v34 = *(const char **)v60;
            v3 = 1038839701;
          }
          else if ( v3 > -1155919955 )
          {
            if ( v44 == 1 )
              v3 = 1609266206;
            else
              v3 = -1781655590;
          }
          else if ( v3 > -1237920251 )
          {
            vm = (JavaVM *)sub_2E738();
            v44 = (int)vm;
            v3 = -1155919954;
          }
          else if ( v3 > -1413870338 )
          {
            v3 = 542546872;
          }
          else if ( v3 > -1525365596 )
          {
            v51 = v52;
            v3 = 1027871974;
          }
          else if ( v3 > -1591680164 )
          {
            v41 = *off_DFF18;
            v3 = 1182817589;
          }
          else if ( v3 > -1618151005 )
          {
            v42 = v30;
            memset(v30, 0, 0x7D0u);
            v25 = v30;
            v16 = getpid();
            sprintf(v25, "/proc/%d/cmdline", v16);
            vm = (JavaVM *)fopen(v25, "r");
            v43 = (FILE *)vm;
            v3 = 1433580933;
          }
          else if ( v3 > -1665109334 )
          {
            v3 = -139557227;
          }
          else if ( v3 > -1679856595 )
          {
            for ( k = -1119912898; ; k = -1679727783 )
            {
              while ( 1 )
              {
                while ( 1 )
                {
                  while ( 1 )
                  {
                    while ( 1 )
                    {
                      while ( k > 504275913 )
                      {
                        sprintf(v56, "/data/data/%s/.hide/%s", v55, v58);
                        vm = (JavaVM *)remove(v56);
                        v57 = (int)vm;
                        k = 308794308;
                      }
                      if ( k <= 308794307 )
                        break;
                      if ( v57 )
                        k = -158042328;
                      else
                        k = -1095053525;
                    }
                    if ( k <= -158042329 )
                      break;
                    v9 = k == -158042328;
                    k = -1095053525;
                    if ( !v9 )
                    {
                      while ( 1 )
                        ;
                    }
                  }
                  if ( k > -1499369114 )
                    break;
                  v18 = (crazy *)memset(v54, 0, 0x100u);
                  crazy::GetPackageName(v18);
                  for ( l = -1458226292; l == -1458226292; l = -1943834868 )
                    v59 = (JavaVM *)&v53;
                  v55 = (const char *)*v59;
                  crazy::String::~String((crazy::String *)&v53);
                  k = -1499369113;
                }
                if ( k != -1499369113 )
                  break;
                v56 = (char *)&v60;
                vm = (JavaVM *)sub_2E728();
                v58 = (const char *)vm;
                k = 504275914;
              }
              if ( k != -1119912898 )
                break;
              v54 = &v60;
            }
            v3 = -853626539;
          }
          else
          {
            if ( v3 > -1719305537 )
            {
              v3 = 1873022921;
              v2 = v27;
              goto LABEL_2;
            }
            v3 = -139557227;
            if ( v4 != -1782315966 )
            {
              if ( v4 == -1781762611 )
              {
                v40 = v31;
                fscanf(v43, "%s", v31);
                fclose(v43);
                vm = (JavaVM *)strchr(v40, 58);
                if ( vm )
                  v3 = 2071858716;
                else
                  v3 = 117134185;
              }
              else
              {
                v49 = v52;
                v3 = 585706881;
              }
            }
          }
        }
      }
    }
    else if ( v50 )
    {
      v3 = 117134185;
    }
    else
    {
      v3 = -1974907953;
    }
  }
}
```
反混淆后的代码
```c
jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
  int v2; // w9
  _JNIEnv *v3; // x1
  _BOOL4 v5; // w8
  crazy *v6; // x0
  int v7; // w8
  crazy *v8; // x0
  _JNIEnv *v9; // x1
  const char *v10; // x0
  _JNIEnv *v12; // x1
  crazy *v13; // x0
  crazy *v14; // x0
  const char *v15; // x0
  crazy *v16; // x0
  _JNIEnv *v17; // x1
  int v18; // w0
  crazy *v19; // x8
  unsigned int v20; // w0
  crazy *v21; // x0
  __int64 v23; // [xsp-FD0h] [xbp-1240h]
  __int64 v24; // [xsp-FC0h] [xbp-1230h]
  __int64 v25; // [xsp-FA0h] [xbp-1210h]
  __int64 v26; // [xsp-7D0h] [xbp-A40h]
  char *v27; // [xsp+8h] [xbp-268h]
  void *v28; // [xsp+10h] [xbp-260h]
  int v29; // [xsp+18h] [xbp-258h]
  int v30; // [xsp+1Ch] [xbp-254h]
  JavaVM *v31; // [xsp+20h] [xbp-250h]
  char *v32; // [xsp+28h] [xbp-248h]
  char *v33; // [xsp+30h] [xbp-240h]
  crazy::String *v34; // [xsp+38h] [xbp-238h]
  void (__fastcall **v35)(JavaVM *, void *); // [xsp+40h] [xbp-230h]
  const char *v36; // [xsp+48h] [xbp-228h]
  int v37; // [xsp+54h] [xbp-21Ch]
  int v38; // [xsp+58h] [xbp-218h]
  int v39; // [xsp+5Ch] [xbp-214h]
  const char *v40; // [xsp+60h] [xbp-210h]
  char *v41; // [xsp+68h] [xbp-208h]
  const char *v42; // [xsp+70h] [xbp-200h]
  int v43; // [xsp+7Ch] [xbp-1F4h]
  char *v44; // [xsp+80h] [xbp-1F0h]
  FILE *v45; // [xsp+88h] [xbp-1E8h]
  int v46; // [xsp+94h] [xbp-1DCh]
  crazy *v47; // [xsp+98h] [xbp-1D8h]
  __int64 v48; // [xsp+A0h] [xbp-1D0h]
  int v49; // [xsp+A8h] [xbp-1C8h]
  int v50; // [xsp+ACh] [xbp-1C4h]
  crazy *v51; // [xsp+B0h] [xbp-1C0h]
  char *v52; // [xsp+B8h] [xbp-1B8h]
  crazy *v53; // [xsp+C0h] [xbp-1B0h]
  crazy *v54; // [xsp+C8h] [xbp-1A8h]
  jint (**v55)(JavaVM *, void **, jint); // [xsp+D0h] [xbp-1A0h]
  crazy::String **v56; // [xsp+E8h] [xbp-188h]
  const char *v57; // [xsp+F0h] [xbp-180h]
  char *v58; // [xsp+F8h] [xbp-178h]
  int v59; // [xsp+104h] [xbp-16Ch]
  const char *v60; // [xsp+108h] [xbp-168h]
  JavaVM *v61; // [xsp+110h] [xbp-160h]
  crazy::String *v62; // [xsp+118h] [xbp-158h]
  __int64 v63; // [xsp+218h] [xbp-58h]

  v28 = reserved;
  v31 = vm;
  v63 = *(_QWORD *)off_DFF90;
  v29 = v2;
  v30 = v2;
  v32 = (char *)&v26;
  v33 = (char *)&v25;
  v34 = (crazy::String *)&v24;
  v35 = (void (__fastcall **)(JavaVM *, void *))&v23;
  v54 = 0LL;
  v61 = vm;
  v55 = &(*vm)->GetEnv;
  v62 = (crazy::String *)*v55;
  if ( ((unsigned int (__fastcall *)(JavaVM *, crazy **, __int64))v62)(vm, &v54, 65540LL) != 0 )
    return -1;
  v60 = (const char *)v54;
  v61 = *(JavaVM **)v54;
  v55 = (jint (**)(JavaVM *, void **, jint))(v61 + 219);
  v62 = (crazy::String *)v61[219];
  ((void (*)(void))v62)();
  v16 = v54;
  *off_DFFF8 = (__int64)v54;
  v18 = crazy::GetApiLevel(v16, v17);
  v19 = v54;
  *off_DFF18 = v18;
  v47 = v19;
  v10 = (const char *)crazy::GetPlatformVersion(v19, v9);
  if ( strchr(v10, 77) != 0LL )
    *off_DFF18 = 23;
  v38 = *off_DFF18;
  if ( v38 > 23 )
    *off_DFEE8 = 1;
  v49 = sub_2E738();
  if ( v49 == 2 )
  {
    v53 = v54;
    v7 = sub_76F60(v53) & 1 ? -1618151004 : -990688990;
    if ( v7 > -990688991 )
      return -1;
  }
  v44 = v32;
  memset(v32, 0, 0x7D0u);
  v27 = v32;
  v20 = getpid();
  sprintf(v27, "/proc/%d/cmdline", v20);
  v45 = fopen(v27, "r");
  if ( v45 != 0LL )
  {
    v41 = v33;
    memset(v33, 0, 0x7D0u);
    v42 = v33;
    fscanf(v45, "%s", v33);
    fclose(v45);
    v5 = strchr(v42, 58) == 0LL;
    if ( v5 || (v52 = strstr(v42, "sg.bigo.enterprise.live:service"), v52 != 0LL) )
      anti_debug_start();
  }
  v43 = *off_DFF18;
  if ( v43 == 15 )
    j_aop_init();
  anti_section_hook();
  v13 = (crazy *)crazy::checkSignature_1(v54, v12);
  if ( ((unsigned __int8)v13 & 1) == 0 )
    crazy::AbortProcess(v13);
  v14 = (crazy *)sub_2E998();
  v40 = (const char *)v14;
  if ( *(_BYTE *)v14 )
  {
    crazy::GetPackageName(v14);
    v62 = v34;
    v36 = *(const char **)v34;
    v6 = (crazy *)strcmp(v36, v40);
    v37 = (int)v6;
    if ( v37 != 0 )
      crazy::AbortProcess(v6);
    crazy::String::~String(v34);
  }
  v46 = sub_2E738();
  if ( v46 == 1 )
  {
    v50 = sub_F688();
    if ( v50 == 0 )
      return -1;
  }
  v51 = v54;
  v8 = (crazy *)crazy::checkdex_1(v54, v3);
  if ( ((unsigned __int8)v8 & 1) == 0 )
    crazy::AbortProcess(v8);
  v39 = sub_E7EC(*off_DFE98[0], "JNI_OnLoad", v35);
  if ( v39 != 0 )
    (*v35)(v31, v28);
  v15 = (const char *)sub_2E728();
  v48 = strlen(v15);
  if ( v48 != 0 )
  {
    v56 = &v62;
    v21 = (crazy *)memset(&v62, 0, 0x100u);
    crazy::GetPackageName(v21);
    v61 = (JavaVM *)&v55;
    v57 = (const char *)v55;
    crazy::String::~String((crazy::String *)&v55);
    v58 = (char *)&v62;
    v60 = (const char *)sub_2E728();
    sprintf(v58, "/data/data/%s/.hide/%s", v57, v60);
    v59 = remove(v58);
  }
  return 65540;
}
```
## 参考资源
* 思路和部分代码源于[llvm-deobfuscator](https://github.com/RPISEC/llvm-deobfuscator.git)
* z3相关代码源于[f-ing-around-with-binaryninja](https://github.com/joshwatson/f-ing-around-with-binaryninja.git)
