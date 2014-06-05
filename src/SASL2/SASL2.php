<?php
// +-----------------------------------------------------------------------+
// | Copyright (c) 2002-2003 Richard Heyes                                 |
// | All rights reserved.                                                  |
// |                                                                       |
// | Redistribution and use in source and binary forms, with or without    |
// | modification, are permitted provided that the following conditions    |
// | are met:                                                              |
// |                                                                       |
// | o Redistributions of source code must retain the above copyright      |
// |   notice, this list of conditions and the following disclaimer.       |
// | o Redistributions in binary form must reproduce the above copyright   |
// |   notice, this list of conditions and the following disclaimer in the |
// |   documentation and/or other materials provided with the distribution.|
// | o The names of the authors may not be used to endorse or promote      |
// |   products derived from this software without specific prior written  |
// |   permission.                                                         |
// |                                                                       |
// | THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS   |
// | "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT     |
// | LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR |
// | A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT  |
// | OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, |
// | SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT      |
// | LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, |
// | DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY |
// | THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT   |
// | (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE |
// | OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.  |
// |                                                                       |
// +-----------------------------------------------------------------------+
// | Author: Richard Heyes <richard@php.net>                               |
// +-----------------------------------------------------------------------+
//
// $Id$

/**
* Client implementation of various SASL mechanisms
*
* @author  Richard Heyes <richard@php.net>
* @access  public
* @version 1.0
* @package Auth_SASL2
*/

namespace SASL2;

use SASL2\Auth\Anonymous;
use SASL2\Auth\Login;
use SASL2\Auth\Plain;
use SASL2\Auth\External;
use SASL2\Auth\CramMD5;
use SASL2\Auth\DigestMD5;
use SASL2\Auth\SCRAM;

class SASL2
{
    /**
    * Factory class. Returns an object of the request
    * type.
    *
    * @param string $type One of: Anonymous
    *                             Plain
    *                             CramMD5
    *                             DigestMD5
    *                             SCRAM-* (any mechanism of the SCRAM family)
    *                     Types are not case sensitive
    */
    function factory($type)
    {
        $classname = 'SASL2\Auth\\';
        switch (strtolower($type)) {
            case 'anonymous':
                $classname .= 'Anonymous';
                break;

            case 'login':
                $classname .= 'Login';
                break;

            case 'plain':
                $classname .= 'Plain';
                break;

            case 'external':
                $classname .= 'External';
                break;

            case 'crammd5':
                // $msg = 'Deprecated mechanism name. Use IANA-registered name: CRAM-MD5.';
                // trigger_error($msg, E_USER_DEPRECATED);
            case 'cram-md5':
                $classname .= 'CramMD5';
                break;

            case 'digestmd5':
                // $msg = 'Deprecated mechanism name. Use IANA-registered name: DIGEST-MD5.';
                // trigger_error($msg, E_USER_DEPRECATED);
            case 'digest-md5':
                // $msg = 'DIGEST-MD5 is a deprecated SASL mechanism as per RFC-6331. Using it could be a security risk.';
                // trigger_error($msg, E_USER_NOTICE);
                $classname .= 'DigestMD5';
                break;

            default:
                $scram = '/^SCRAM-(.{1,9})$/i';
                if (preg_match($scram, $type, $matches))
                {
                    $hash = $matches[1];
                    $classname .= 'SCRAM';
                    $parameter = $hash;
                    break;
                }
                throw new InvalidArgumentException('Invalid SASL mechanism type');
                break;
        }

        if (isset($parameter)) {
            $obj = new $classname($parameter);
        } else {
            $obj = new $classname();
        }

        return $obj;
    }
}


