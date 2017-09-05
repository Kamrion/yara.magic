// based on https://en.wikipedia.org/wiki/List_of_file_signatures

rule magic_RPM_Package
{
    meta:
        description = "RedHat Package Manager (RPM) package"

    strings:
        $magic = { ED AB EE DB }

    condition:
        $magic at 0
}

rule magic_Kindle_Update
{
    meta:
        description = "Amazon Kindle Update Package (*.bin)"

    strings:
        $magic = { 53 50 30 31 }

    condition:
        $magic at 0
}
///* wtf???
rule magic_Palm_DB_File
{
    meta:
        description = "PalmPilot Database/Document File"

    strings:
        $magic = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        $magic at 11
}
//*/ 
rule magic_Palm_Calendar_Archive
{
    meta:
        description = "Palm Desktop Calendar Archive"

    strings:
        $dba = { BE BA FE CA }
		$tda = { 00 01 44 54 }

    condition:
        $dba at 0 
		or $tda at 0
}

rule magic_Palm_ToDo_Archive
{
    meta:
        description = "Palm Desktop To Do Archive"

    strings:
        $magic = { 00 01 42 44 }

    condition:
        $magic at 0
}
///* slow 	
rule magic_Palm_Desktop_Data_File
{
    meta:
        description = "Palm Desktop Data File (Access format)"

    strings:
        $magic = { 00 01 00 00 }

    condition:
        $magic at 0
} //*/
///* slow 	
rule magic_ico
{
    meta:
        description = "Computer icon encoded in ICO file format"

    strings:
        $magic = { 00 00 01 00 }

    condition:
        $magic at 0
}
//*/
rule magic_3gp
{
    meta:
        description = "3rd Generation Partnership Project 3GPP and 3GPP2 multimedia files"
		category = "multimedia"

    strings:
        $magic = { 66 74 79 70 33 67 }

    condition:
        $magic at 4
}

rule magic_LZW
{
    meta:
        description = "compressed file (often tar zip) using Lempel-Ziv-Welch algorithm"
		category = "archive"

    strings:
        $magic = { 1F 9D }

    condition:
        $magic at 0
}

rule magic_LZH
{
    meta:
        description = "compressed file (often tar zip) using LZH algorithm"
		category = "archive"

    strings:
        $magic = { 1F A0 }

    condition:
        $magic at 0
}

rule magic_Amiga_backup
{
    meta:
        description = "File or tape containing a backup done with AmiBack on an Amiga"

    strings:
        $magic = { 42 41 43 4B 4D 49 4B 45 44 49 53 4B }

    condition:
        $magic at 0
}

rule magic_Gif
{
    meta:
        description = "Image file encoded in the Graphics Interchange Format (GIF)"
		category = "multimedia"

    strings:
        $magic1 = { 47 49 46 38 37 61 }
        $magic2 = { 47 49 46 38 39 61 }
		
    condition:
        $magic1 at 0 
		or $magic2 at 0
}


rule magic_Tiff
{
    meta:
        description = "Tagged Image File Format"
		category = "multimedia"

    strings:
        $magic1 = { 49 49 2A 00 }
        $magic2 = { 4D 4D 00 2A }
		
    condition:
        $magic1 at 0 
		or $magic2 at 0
}

rule magic_Cr2
{
    meta:
        description = "Canon RAW Format Version 2"
		category = "multimedia"

    strings:
        $magic = { 49 49 2A 00 10 00 00 00 43 52 }
		
    condition:
        $magic at 0 
}

rule magic_Cin
{
    meta:
        description = "Kodak Cineon image"
		category = "multimedia"

    strings:
        $magic = { 80 2A 5F D7 }
		
    condition:
        $magic at 0 
}

rule magic_RNC
{
    meta:
        description = "Compressed file using Rob Northen Compression (version 1 and 2) algorithm"
		category = "archive"

    strings:
        $v1 = { 52 4E 43 01 }
        $v2 = { 52 4E 43 02 }
				
    condition:
        $v1 at 0 
		or $v2 at 0
}

rule magic_dpx
{
    meta:
        description = "SMPTE DPX image"
		category = "multimedia"

    strings:
        $big_endian = { 53 44 50 58 }
        $ltl_endian = { 58 50 44 53 }
				
    condition:
        $big_endian at 0 
		or $ltl_endian at 0
}

rule magic_exr
{
    meta:
        description = "OpenEXR image"
		category = "multimedia"

    strings:
        $magic = { 76 2F 31 01 }
				
    condition:
        $magic at 0
}

rule magic_bpg
{
    meta:
        description = "Better Portable Graphics format"
		category = "multimedia"

    strings:
        $magic = { 42 50 47 FB }
				
    condition:
        $magic at 0
}

rule magic_jpeg
{
    meta:
        description = "JPEG raw or in the JFIF or Exif file format"
		category = "multimedia"

    strings:
        $var1 = { FF D8 FF DB FB }
        $var2 = { FF D8 FF E0 ?? ?? 4A 46 }
        $var3 = { FF D8 FF E1 ?? ?? 45 78 69 66 00 00 }
				
    condition:
        for any of them : ($ at 0)
}

rule magic_iff
{
    meta:
        description = "Interchange File Format"
		category = "container"

    strings:
        $magic = { 46 4F 52 4D }
				
    condition:
        $magic at 0
}

rule magic_iff_ilbm
{
    meta:
        description = "IFF Interleaved Bitmap Image"
		category = "multimedia"

    strings:
        $magic = { 49 4C 42 4D }
				
    condition:
        magic_iff 
		and $magic
}

rule magic_iff_8svx
{
    meta:
        description = "IFF 8-Bit Sampled Voice"
		category = "multimedia"

    strings:
        $magic = { 38 53 56 58 }
				
    condition:
        magic_iff 
		and $magic
}

rule magic_iff_acbm
{
    meta:
        description = "Amiga Contiguous Bitmap (.acbm)"
		category = "multimedia"

    strings:
        $magic = { 41 43 42 4D }
				
    condition:
        magic_iff 
		and $magic
}

rule magic_iff_anbm
{
    meta:
        description = "IFF Animated Bitmap"
		category = "multimedia"

    strings:
        $magic = { 41 4E 42 4D }
				
    condition:
        magic_iff 
		and $magic
}

rule magic_iff_anim
{
    meta:
        description = "IFF CEL Animation"
		category = "multimedia"

    strings:
        $magic = { 41 4E 49 4D }
				
    condition:
        magic_iff 
		and $magic
}

rule magic_iff_faxx
{
    meta:
        description = "IFF Facsimile Image"
		category = "multimedia"

    strings:
        $magic = { 46 41 58 58 }
				
    condition:
        magic_iff 
		and $magic
}

rule magic_iff_ftxt
{
    meta:
        description = "IFF Formatted Text"

    strings:
        $magic = { 46 54 58 54 }
				
    condition:
        magic_iff 
		and $magic
}

rule magic_iff_smus
{
    meta:
        description = "IFF Simple Musical Score"

    strings:
        $magic = { 53 4D 55 53 }
				
    condition:
        magic_iff 
		and $magic
}

rule magic_iff_cmus
{
    meta:
        description = "IFF Musical Score"

    strings:
        $magic = { 43 4D 55 53 }
				
    condition:
        magic_iff 
		and $magic
}

rule magic_iff_yuvn
{
    meta:
        description = "IFF YUV Image"
		category = "multimedia"
		
    strings:
        $magic = { 59 55 56 4E }
				
    condition:
        magic_iff 
		and $magic
}

rule magic_iff_aiff
{
    meta:
        description = "Audio Interchange File Format"
		category = "multimedia"
		
    strings:
        $magic = { 41 49 46 46 }
				
    condition:
        magic_iff 
		and $magic
}

rule magic_idx
{
    meta:
        description = "Index file to a file or tape containing a backup done with AmiBack on an Amiga"
		
    strings:
        $magic = { 49 4E 44 58 }
				
    condition:
		$magic at 0
}

rule magic_lz
{
    meta:
        description = "lzip compressed file"
		category = "archive"
		
    strings:
        $magic = { 4C 5A 49 50 }
				
    condition:
		$magic at 0
}

rule magic_exe
{
    meta:
        description = "DOS MZ executable file format and its descendants (including NE and PE)"
		
    strings:
        $magic = { 4D 5A }
				
    condition:
		$magic at 0
}

rule magic_zip
{
    meta:
        description = "zip file format and formats based on it, such as JAR, ODF, OOXML"
		category = "archive"
		
    strings:
        $magic = { 50 4B 03 04 }
        $empty = { 50 4B 05 06 }	// empty archive
        $spanned = { 50 4B 07 08 }	// spanned archive
				
    condition:
		$magic at 0
		or $empty at 0
		or $spanned at 0
}

rule magic_rar
{
    meta:
        description = "RAR archive"
		category = "archive"
		
    strings:
        $magic1 = { 52 61 72 21 1A 07 00 }	// RAR archive version 1.50 onwards
        $magic5 = { 52 61 72 21 1A 07 01 00 }	// RAR archive version 5.0 onwards
				
    condition:
		$magic1 at 0
		or $magic5 at 0
}

rule magic_elf
{
    meta:
        description = "Executable and Linkable Format"
		
    strings:
        $magic = { 7F 45 4C 46 }
				
    condition:
		$magic at 0
}

rule magic_png
{
    meta:
        description = "Image encoded in the Portable Network Graphics format"
		category = "multimedia"
		
    strings:
        $magic = { 89 50 4E 47 0D 0A 1A 0A }
				
    condition:
		$magic at 0
}

rule magic_jvm
{
    meta:
        description = "Java class file, Mach-O Fat Binary"
		
    strings:
        $magic = { CA FE BA BE }
				
    condition:
		$magic at 0
}

rule magic_txt_utf8
{
    meta:
        description = "UTF-8 encoded Unicode byte order mark, commonly seen in text files"
		
    strings:
        $magic = { EF BB BF }
				
    condition:
		$magic at 0
}

/*
rule magic_mach32 + reverse
rule magic_mach64 + reverse
непонятная хрень в таблице, пропускаем
*/
///* slow 	
rule magic_utf16
{
    meta:
        description = "Text file encoded in little-endian 16-bit Unicode Transfer Format"
		
    strings:
        $magic = { FF FE }
		$notMagic = { FF FE 00 00 }
				
    condition:
		$magic at 0
		and not ($notMagic at 0)
} //*/
///* slow 	
rule magic_utf32
{
    meta:
        description = "Text file encoded in little-endian 32-bit Unicode Transfer Format"
		
    strings:
        $magic = { FF FE 00 00 }
				
    condition:
		$magic at 0
}//*/ 

rule magic_ps
{
    meta:
        description = "PostScript document"
		
    strings:
        $magic = { 25 21 50 53 }
				
    condition:
		$magic at 0
}

rule magic_pdf
{
    meta:
        description = "PDF document"
		
    strings:
        $magic = { 25 50 44 46 }
				
    condition:
		$magic at 0
}

rule magic_asf
{
    meta:
        description = "Advanced Systems Format"
		category = "container"
		
    strings:
        $magic = { 30 26 B2 75 8E 66 CF 11 A6 D9 00 AA 00 62 CE 6C }
				
    condition:
		$magic at 0
}

rule magic_sdi
{
    meta:
        description = "System Deployment Image, a disk image format used by Microsoft"
		
    strings:
        $magic = { 24 53 44 49 30 30 30 31 }
				
    condition:
		$magic at 0
}

rule magic_ogg
{
    meta:
        description = "Ogg, an open source media container format"
		category = "container"
		
    strings:
        $magic = { 4F 67 67 53 }
				
    condition:
		$magic at 0
}

rule magic_psd
{
    meta:
        description = "Photoshop Document file, Adobe Photoshop's native file format"
		category = "multimedia"
		
    strings:
        $magic = { 38 42 50 53 }
				
    condition:
		$magic at 0
}

rule magic_wav
{
    meta:
        description = "Waveform Audio File Format"
		category = "multimedia"
		
    strings:
        $magic = { 52 49 46 46 ?? ?? ?? ?? 57 41 56 45 }
				
    condition:
		$magic at 0
}

rule magic_avi
{
    meta:
        description = "Audio Video Interleave video format"
		category = "container"
		
    strings:
        $magic = { 52 49 46 46 ?? ?? ?? ?? 41 56 49 20 }
				
    condition:
		$magic at 0
}

rule magic_mp3
{
    meta:
        description = "MPEG-1 Layer 3 file"
		category = "multimedia"
		
    strings:
        $WithoutTag = { FF FB }	// MPEG-1 Layer 3 file without an ID3 tag or with an ID3v1 tag
		$WithTag = { 49 44 33 }	// MP3 file with an ID3v2 container
				
    condition:
		$WithoutTag at 0 or
		$WithTag at 0
}

rule magic_bmp
{
    meta:
        description = "BMP file, a bitmap format used mostly in the Windows world"
		category = "multimedia"
		
    strings:
        $magic = { 42 4D }
				
    condition:
		$magic at 0
}

rule magic_iso
{
    meta:
        description = "ISO9660 CD/DVD image file"
		category = "container"
		
    strings:
        $magic = { 43 44 30 30 31 }
				
    condition:
		$magic at 0	// filesignatures.net
		or $magic at 0x8001	// wiki
		or $magic at 0x8801	// wiki
		or $magic at 0x9001	// wiki
}

///*
rule magic_fits
{
    meta:
        description = "Flexible Image Transport System"
		
    strings:
        $magic1 = { 53 49 4D 50 4C 45 20 20 }
        $magic2 = { 3D 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 54 }
		
				
    condition:
		$magic1 at 0
		or $magic2
}
//*/

rule magic_flac
{
    meta:
        description = "Free Lossless Audio Codec"
		category = "multimedia"
		
    strings:
        $magic = {66 4C 61 43}
				
    condition:
		$magic at 0	
}

rule magic_midi
{
    meta:
        description = "MIDI sound file"
		category = "multimedia"
		
    strings:
        $magic = { 4D 54 68 64 }
				
    condition:
		$magic at 0	
}

rule magic_cfbf
{
    meta:
        description = "Compound File Binary Format, a container format used for document by older versions of Microsoft Office"
		
    strings:
        $magic = { D0 CF 11 E0 A1 B1 1A E1 }
				
    condition:
		$magic
}

rule magic_dex
{
    meta:
        description = "Dalvik Executable"
		
    strings:
        $magic = { 64 65 78 0A 30 33 35 00 }
				
    condition:
		$magic at 0
}

rule magic_vmdk
{
    meta:
        description = "VMDK files"
		
    strings:
        $magic = { 4B 44 4D }
				
    condition:
		$magic at 0
}

rule magic_crx
{
    meta:
        description = "Google Chrome extension or packaged app"
		
    strings:
        $magic = { 43 72 32 34 }
				
    condition:
		$magic at 0
}

rule magic_fh8
{
    meta:
        description = "FreeHand 8 document"
		
    strings:
        $magic = { 41 47 44 33 }
				
    condition:
		$magic at 0
}

rule magic_cwk
{
    meta:
        description = "AppleWorks document"
		
    strings:
        $v5 = { 05 07 00 00 42 4F 42 4F 05 07 00 00 00 00 00 00 00 00 00 00 00 01 }
        $v6 = { 06 07 E1 00 42 4F 42 4F 06 07 E1 00 00 00 00 00 00 00 00 00 00 01 }
				
    condition:
		$v5 at 0
		or $v6 at 0
}

rule magic_toast
{
    meta:
        description = "Roxio Toast disc image file, also some .dmg-files begin with same bytes"
		category = "container"
		
    strings:
        $magic1 = { 45 52 02 00 00 00 }
        $magic2 = { 8B 45 52 02 00 00 00 }
				
    condition:
		$magic1 at 0
		or $magic2 at 0
}

rule magic_dmg
{
    meta:
        description = "Apple Disk Image file"
		category = "container"
		
    strings:
        $magic = { 78 01 73 0D 62 62 60 }
				
    condition:
		$magic at 0
}

rule magic_xar
{
    meta:
        description = "eXtensible ARchive format"
		category = "archive"
		
    strings:
        $magic = { 78 61 72 21 }
				
    condition:
		$magic at 0
}

rule magic_dat
{
    meta:
        description = "Windows Files And Settings Transfer Repository"
		
    strings:
        $magic = { 50 4D 4F 43 43 4D 4F 43 }
				
    condition:
		$magic at 0
}

rule magic_nes
{
    meta:
        description = "Nintendo Entertainment System ROM file"
		// category = "container"
		
    strings:
        $magic = { 4E 45 53 1A }
				
    condition:
		$magic at 0
}

rule magic_tar
{
    meta:
        description = "tar archive"
		category = "archive"
		
    strings:
        $magic = { 75 73 74 61 72 00 30 30 }
		$alt_magic = { 75 73 74 61 72 20 20 00 }
				
    condition:
		$magic at 0x101
		or $alt_magic at 0x101
}

rule magic_tox
{
    meta:
        description = "Open source portable voxel file"
		
    strings:
        $magic = { 74 6F 78 33 }
				
    condition:
		$magic at 0		
}

rule magic_mlv
{
    meta:
        description = "Magic Lantern Video file"
		category = "multimedia"
		
    strings:
        $magic = { 4D 4C 56 49 }
				
    condition:
		$magic at 0		
}

///*
rule magic_wubdc
{
    meta:
        description = "Windows Update Binary Delta Compression"
		
    strings:
        $magic = { 44 43 4D 01 50 41 33 30 }
				
    condition:
		$magic at 0		
}
//*/

rule magic_7z
{
    meta:
        description = "7-Zip File Format"
		category = "archive"
		
    strings:
        $magic = { 37 7A BC AF 27 1C }
				
    condition:
		$magic at 0		
}

rule magic_gzip
{
    meta:
        description = "GZIP file format"
		category = "archive"
		
    strings:
        $magic = { 1F 8B }
				
    condition:
		$magic at 0
}

rule magic_lz4
{
    meta:
        description = "LZ4 Frame Format"
		category = "archive"
		
    strings:
        $magic = { 04 22 4D 18 }
				
    condition:
		$magic at 0
}

rule magic_cab
{
    meta:
        description = "Microsoft Cabinet file"
		category = "archive"
		
    strings:
        $magic = { 4D 53 43 46 }
				
    condition:
		$magic at 0
}

rule magic_quantium
{
    meta:
        description = "Microsoft compressed file in Quantum format, used prior to Windows XP"
		category = "archive"
		
    strings:
        $magic = { 53 5A 44 44 88 F0 27 33 }
				
    condition:
		$magic at 0
}

rule magic_flif
{
    meta:
        description = "Free Lossless Image Format"
		category = "multimedia"
		
    strings:
        $magic = { 46 4C 49 46 }
				
    condition:
		$magic at 0
}

rule magic_mkv
{
    meta:
        description = "Matroska media container"
		category = "container"
		
    strings:
        $magic = { 1A 45 DF A3 }
				
    condition:
		$magic at 0
}

// "SEAN : Session Analysis" Training file - skipped

rule magic_djvu
{
    meta:
        description = "DjVu document"
		
    strings:
        $magic = { 41 54 26 54 46 4F 52 4D ?? ?? ?? ?? 44 4A 56 }
				
    condition:
		$magic at 0
}

rule magic_der	//???
{
    meta:
        description = "DER encoded X.509 certificate"
		
    strings:
        $magic = { 30 82 }
				
    condition:
		$magic at 0
}

rule magic_dcm	//???
{
    meta:
        description = "DICOM Medical File Format"
		
    strings:
        $magic = { 44 49 43 4D }
				
    condition:
		$magic at 128
}

rule magic_woff	//???
{
    meta:
        description = "WOFF File Format"
		
    strings:
        $v1 = { 77 4F 46 46 }
        $v2 = { 77 4F 46 32 }
				
    condition:
		$v1 at 0
		or $v2 at 0
}

rule magic_xml
{
    meta:
        description = "eXtensible Markup Language when using the ASCII character encoding"
		
    strings:
        $magic = { 3c 3f 78 6d 6c 20 }
        $magicASCII = "<?xml"
				
    condition:
		$magic at 0
		or $magicASCII at 0
}

rule magic_wasm	//???
{
    meta:
        description = "WebAssembly binary format"
		
    strings:
        $magic = { 6d 73 61 00 }
				
    condition:
		$magic at 0
}

rule magic_lep	//???
{
    meta:
        description = "Lepton compressed JPEG image"
		
    strings:
        $magic = { cf 84 01 }
				
    condition:
		$magic at 0
}

rule magic_swf
{
    meta:
        description = "flash .swf"
		
    strings:
        $magic = { 43 57 53 }
		$magic_alt = { 46 57 53 }
				
    condition:
		$magic at 0
		or $magic_alt at 0
}

rule magic_deb
{
    meta:
        description = "linux deb file"
		
    strings:
        $magic = { 21 3C 61 72 63 68 3E }
				
    condition:
		$magic at 0
}

rule magic_ulmage //???
{
    meta:
        description = "U-Boot / uImage"
		
    strings:
        $magic = { 7B 5C 72 74 66 31 }
				
    condition:
		$magic at 0
}

