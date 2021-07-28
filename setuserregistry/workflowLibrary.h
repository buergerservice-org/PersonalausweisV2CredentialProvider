// workflowLibrary.h
// read data of german Personalausweis with selfauthentication from AusweisApp2
// Copyright (C) 2021 buergerservice.org e.V. <KeePerso@buergerservice.org>
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

#pragma once

#include <string>


namespace workflowLibrary
{
	class workflow
	{
	public:
		std::string startworkflow(std::string PINstring);
		std::string getkeypad();
		std::string getcertificate();
		std::string readjson(std::string);

		//openssl wrapper
		int encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key,
			unsigned char* iv, unsigned char* ciphertext);
		int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key,
			unsigned char* iv, unsigned char* plaintext);
		void BIO_dump_fp_wrap(FILE* fp, char const* s, int len);

		//personaldata
		std::string personalStyledString;
		std::string AcademicTitle;
		std::string ArtisticName;
		std::string BirthName;
		std::string DateOfBirth;
		std::string DocumentType;
		std::string FamilyNames;
		std::string GivenNames;
		std::string IssuingState;
		std::string Nationality;
		//personaldata PlaceOfBirth
		std::string PlaceOfBirth;
		//personaldata PlaceOfResidence
		std::string City;
		std::string Country;
		std::string Street;
		std::string ZipCode;

		// certificate
		std::string certificateStyledString;
		// certificate description
		std::string issuerName;
		std::string issuerUrl;
		std::string purpose;
		std::string subjectName;
		std::string subjectUrl;
		std::string termsOfUsage;
		// certificate validity
		std::string effectiveDate;
		std::string expirationDate;

	private:
		bool keypad;

	};
}
