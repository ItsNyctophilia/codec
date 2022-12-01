int shift_24_bit_int(int num)
// Reverses the byte order of a 24 bit integer. Returns the reversed
// integer.
{
	int tmp_len = 0;
	//tmp_len = num & 0xFF;
	//tmp_len = (num >> 8) & 0xFF;
	//tmp_len = (num >> 16) & 0xFF;
	char *int_to_convert = (char *)&num;
	char *return_int = (char *)&tmp_len;

	return_int[0] = int_to_convert[3];
	return_int[1] = int_to_convert[2];
	return_int[2] = int_to_convert[1];
	return_int[3] = int_to_convert[0];
	tmp_len = tmp_len >> 8;
	return (tmp_len);
}

float reverse_float(const float num)
// Reverses the byte order of the passed float. Returns the 
// reversed float.
// Syntax taken from Gregor Brandt: https://stackoverflow.com/a/2782742.
{
	float ret_val;
	char *float_to_convert = (char *)&num;
	char *return_float = (char *)&ret_val;

	return_float[0] = float_to_convert[3];
	return_float[1] = float_to_convert[2];
	return_float[2] = float_to_convert[1];
	return_float[3] = float_to_convert[0];

	return (ret_val);
}

double reverse_double(const double num)
// Reverses the byte order of the passed double. Can probably
// be merged with reverse_float later.
{
	double ret_val;
	char *double_to_convert = (char *)&num;
	char *return_double = (char *)&ret_val;

	return_double[0] = double_to_convert[7];
	return_double[1] = double_to_convert[6];
	return_double[2] = double_to_convert[5];
	return_double[3] = double_to_convert[4];
	return_double[4] = double_to_convert[3];
	return_double[5] = double_to_convert[2];
	return_double[6] = double_to_convert[1];
	return_double[7] = double_to_convert[0];

	return (ret_val);
}
