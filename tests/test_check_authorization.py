from va_ondemand import check_authorization
import pytest

DEFAULT_REGION = "us-west-2"


def test_check_authorization_invalid():
    invalid_aws_profile = "test"
    invalid_aws_region = "test-region"
    with pytest.raises(AssertionError):
        assert check_authorization(invalid_aws_profile, invalid_aws_region)


def test_check_authorization_valid():
    test_aws_profile = "infosec-dev-MAWS-Admin"
    test_aws_region = DEFAULT_REGION
    test_api_key = check_authorization(test_aws_profile, test_aws_region)

    assert type(test_api_key) is str
