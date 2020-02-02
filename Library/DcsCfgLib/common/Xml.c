/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2017 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/
#if !defined(_UEFI)
#include <windows.h>
#include <stdio.h>
#else
#include <Uefi.h> 
#include <Library/BaseLib.h> 
#include <Library/BaseMemoryLib.h>

typedef BOOLEAN BOOL;
typedef UINTN size_t;
typedef CHAR16 wchar_t;

#define MAX_STRING_SIZE  0x1000
#define wcscpy                            StrCpy
#define memcpy(dest,source,count)         CopyMem(dest,source,(UINTN)(count))
#define strchr(str,ch)                    ScanMem8((VOID *)(str),AsciiStrSize(str),(UINT8)ch)
#define strcmp                            AsciiStrCmp
#define strcpy(strDest,strSource)         AsciiStrCpyS(strDest,MAX_STRING_SIZE,strSource)
#define strlen(str)                       (size_t)(AsciiStrnLenS(str,MAX_STRING_SIZE))
#define strstr                            AsciiStrStr

#pragma warning( disable : 4706 )  //  assignment within conditional expression
#endif
#include "Xml.h"


static BOOL BeginsWith (char *string, char *subString)
{
	while (*string++ == *subString++)
	{
		if (*subString == 0) return TRUE;
		if (*string == 0) return FALSE;
	}

	return FALSE;
}


char *XmlNextNode (char *xmlNode)
{
	char *t = xmlNode + 1;
	while ((t = strchr (t, '<')) != NULL)
	{
		if (t[1] != '/')
			return t;

		t++;
	}

	return NULL;
}


char *XmlFindElement (char *xmlNode, char *nodeName)
{
	char *t = xmlNode;
	size_t nameLen = strlen (nodeName);

	do
	{
		if (BeginsWith (t + 1, nodeName)
			&& (t[nameLen + 1] == '>'
			|| t[nameLen + 1] == ' ')) return t;

	} while (t = XmlNextNode (t));

	return NULL;
}


char *XmlFindElementByAttributeValue (char *xml, char *nodeName, const char *attrName, const char *attrValue)
{
	char attr[2048];

	while (xml = XmlFindElement (xml, nodeName))
	{
		XmlGetAttributeText (xml, attrName, attr, sizeof (attr));
		if (strcmp (attr, attrValue) == 0)
			return xml;

		xml++;
	}

	return NULL;
}


char *XmlGetAttributeText (char *xmlNode, const char *xmlAttrName, char *xmlAttrValue, int xmlAttrValueSize)
{
	char *t = xmlNode;
	char *e = xmlNode;
	int l = 0;

	xmlAttrValue[0] = 0;
	if (t[0] != '<') return NULL;

	e = strchr (e, '>');
	if (e == NULL) return NULL;

	while ((t = strstr (t, xmlAttrName)) && t < e)
	{
		char *o = t + strlen (xmlAttrName);
		if (t[-1] == ' '
			&&
			(BeginsWith (o, "=\"")
			|| BeginsWith (o, "= \"")
			|| BeginsWith (o, " =\"")
			|| BeginsWith (o, " = \""))
			)
			break;

		t++;
	}

	if (t == NULL || t > e) return NULL;

	t = ((char*)strchr (t, '"')) + 1;
	e = strchr (t, '"');
	l = (int)(e - t);
	if (e == NULL || l > xmlAttrValueSize) return NULL;

	memcpy (xmlAttrValue, t, l);
	xmlAttrValue[l] = 0;

	return xmlAttrValue;
}


char *XmlGetNodeText (char *xmlNode, char *xmlText, int xmlTextSize)
{
	char *t = xmlNode;
	char *e = xmlNode + 1;
	int l = 0, i = 0, j = 0;

	xmlText[0] = 0;

	if (t[0] != '<')
		return NULL;

	t = (char*) strchr (t, '>');
	if (t == NULL) return NULL;

	t++;
	e = strchr (e, '<');
	if (e == NULL) return NULL;

	l = (int)(e - t);
	if (e == NULL || l > xmlTextSize) return NULL;

	while (i < l)
	{
		if (BeginsWith (&t[i], "&lt;"))
		{
			xmlText[j++] = '<';
			i += 4;
			continue;
		}
		if (BeginsWith (&t[i], "&gt;"))
		{
			xmlText[j++] = '>';
			i += 4;
			continue;
		}
		if (BeginsWith (&t[i], "&amp;"))
		{
			xmlText[j++] = '&';
			i += 5;
			continue;
		}
		xmlText[j++] = t[i++];
	}
	xmlText[j] = 0;

	return t;
}


char *XmlQuoteText (const char *textSrc, char *textDst, int textDstMaxSize)
{
	char *textDstLast = textDst + textDstMaxSize - 1;

	if (textDstMaxSize == 0)
		return NULL;

	while (*textSrc != 0 && textDst <= textDstLast)
	{
		char c = *textSrc++;
		switch (c)
		{
		case '&':
			if (textDst + 6 > textDstLast)
				return NULL;
			strcpy (textDst, "&amp;");
			textDst += 5;
			continue;

		case '>':
			if (textDst + 5 > textDstLast)
				return NULL;
			strcpy (textDst, "&gt;");
			textDst += 4;
			continue;

		case '<':
			if (textDst + 5 > textDstLast)
				return NULL;
			strcpy (textDst, "&lt;");
			textDst += 4;
			continue;

		default:
			*textDst++ = c;
		}
	}

	if (textDst > textDstLast)
		return NULL;

	*textDst = 0;
	return textDst;
}

wchar_t *XmlQuoteTextW (const wchar_t *textSrc, wchar_t *textDst, int textDstMaxSize)
{
	wchar_t *textDstLast = textDst + textDstMaxSize - 1;

	if (textDstMaxSize == 0)
		return NULL;

	while (*textSrc != 0 && textDst <= textDstLast)
	{
		wchar_t c = *textSrc++;
		switch (c)
		{
		case L'&':
			if (textDst + 6 > textDstLast)
				return NULL;
			wcscpy (textDst, L"&amp;");
			textDst += 5;
			continue;

		case L'>':
			if (textDst + 5 > textDstLast)
				return NULL;
			wcscpy (textDst, L"&gt;");
			textDst += 4;
			continue;

		case L'<':
			if (textDst + 5 > textDstLast)
				return NULL;
			wcscpy (textDst, L"&lt;");
			textDst += 4;
			continue;

		default:
			*textDst++ = c;
		}
	}

	if (textDst > textDstLast)
		return NULL;

	*textDst = 0;
	return textDst;
}

#if !defined(_UEFI)
#pragma warning( default : 4706 )
int XmlWriteHeader (FILE *file)
{
	return fputws (L"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<DiskCrypto>", file);
}


int XmlWriteFooter (FILE *file)
{
	return fputws (L"\n</DiskCrypto>", file);
}
#endif !defined(_UEFI)
