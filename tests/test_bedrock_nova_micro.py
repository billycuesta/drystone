"""Unit tests for Amazon Nova Micro integration via Bedrock."""

import json
from unittest.mock import MagicMock, patch

import pytest

from drystone.agent.client import AgentClient, AgentError


class TestBedrockNovaMicroIntegration:
    """Test Bedrock integration with Amazon Nova Micro model."""

    @pytest.fixture
    def bedrock_client_mock(self):
        """Create mock Bedrock client."""
        with patch('boto3.client') as mock_boto_client:
            mock_client = MagicMock()
            mock_boto_client.return_value = mock_client
            yield mock_client

    @pytest.fixture
    def agent_with_bedrock(self, bedrock_client_mock):
        """Create agent with Bedrock provider."""
        config = {
            'type': 'bedrock',
            'bedrock_access_key_id': 'test-key',
            'bedrock_secret_access_key': 'test-secret',
        }
        agent = AgentClient(provider_config=config)
        return agent

    def test_bedrock_model_id_is_nova_micro(self, agent_with_bedrock):
        """Verify model ID is set to Amazon Nova Micro."""
        assert agent_with_bedrock.bedrock_model_id == "arn:aws:bedrock:eu-west-1:781978598807:inference-profile/eu.amazon.nova-micro-v1:0"

    def test_bedrock_max_tokens_is_5000(self, agent_with_bedrock):
        """Verify max tokens is set to Nova Micro limit (5000)."""
        assert agent_with_bedrock.max_tokens == 5000

    def test_bedrock_temperature_is_zero(self, agent_with_bedrock):
        """Verify temperature is set to 0.0 for deterministic output."""
        assert agent_with_bedrock.temperature == 0.0

    def test_call_bedrock_api_request_format(self, agent_with_bedrock, bedrock_client_mock):
        """Verify request body matches Nova Micro schema."""
        # Mock response
        nova_response = {
            "output": {
                "message": {
                    "content": [
                        {
                            "text": '{"skill": "iam", "findings": [], "summary": {"total_findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "overall_risk_score": 0.0}}'
                        }
                    ]
                }
            }
        }

        mock_response = MagicMock()
        mock_response['body'].read.return_value = json.dumps(nova_response)
        bedrock_client_mock.invoke_model.return_value = mock_response

        # Call with separated prompts
        system_prompt = "You are an AWS security auditor."
        user_prompt = "Analyze the following IAM configuration."

        response = agent_with_bedrock._call_bedrock_api(system_prompt, user_prompt)

        # Verify response was parsed correctly
        assert response == nova_response["output"]["message"]["content"][0]["text"]

        # Verify request was built correctly
        bedrock_client_mock.invoke_model.assert_called_once()
        call_kwargs = bedrock_client_mock.invoke_model.call_args[1]

        # Parse the request body
        request_body = json.loads(call_kwargs['body'])

        # Verify request structure for Nova Micro
        assert 'system' in request_body, "Request must have 'system' array"
        assert isinstance(request_body['system'], list), "'system' must be array"
        assert len(request_body['system']) == 1, "'system' must have one element"
        assert request_body['system'][0]['text'] == system_prompt

        assert 'messages' in request_body, "Request must have 'messages' array"
        assert isinstance(request_body['messages'], list), "'messages' must be array"
        assert request_body['messages'][0]['role'] == 'user'
        assert isinstance(request_body['messages'][0]['content'], list), "'content' must be array"
        assert request_body['messages'][0]['content'][0]['text'] == user_prompt

        assert 'inferenceConfig' in request_body, "Request must have 'inferenceConfig'"
        assert request_body['inferenceConfig']['maxTokens'] == 5000
        assert request_body['inferenceConfig']['temperature'] == 0.0

        assert call_kwargs['modelId'] == "arn:aws:bedrock:eu-west-1:781978598807:inference-profile/eu.amazon.nova-micro-v1:0"

    def test_call_bedrock_api_response_parsing(self, agent_with_bedrock, bedrock_client_mock):
        """Verify response parsing for Nova Micro format."""
        # Valid Nova Micro response
        nova_response = {
            "output": {
                "message": {
                    "content": [
                        {
                            "text": "Test response"
                        }
                    ]
                }
            }
        }

        mock_response = MagicMock()
        mock_response['body'].read.return_value = json.dumps(nova_response)
        bedrock_client_mock.invoke_model.return_value = mock_response

        response = agent_with_bedrock._call_bedrock_api("system", "user")
        assert response == "Test response"

    def test_call_bedrock_api_invalid_response_structure(self, agent_with_bedrock, bedrock_client_mock):
        """Verify error handling for invalid response structure."""
        # Invalid response (missing output)
        invalid_response = {
            "error": "Something went wrong"
        }

        mock_response = MagicMock()
        mock_response['body'].read.return_value = json.dumps(invalid_response)
        bedrock_client_mock.invoke_model.return_value = mock_response

        with pytest.raises(AgentError) as exc_info:
            agent_with_bedrock._call_bedrock_api("system", "user")

        assert "Invalid response structure" in str(exc_info.value)

    def test_call_bedrock_api_missing_nested_keys(self, agent_with_bedrock, bedrock_client_mock):
        """Verify error handling for missing nested keys in response."""
        # Response with partial structure
        partial_response = {
            "output": {
                "message": {
                    # Missing 'content'
                }
            }
        }

        mock_response = MagicMock()
        mock_response['body'].read.return_value = json.dumps(partial_response)
        bedrock_client_mock.invoke_model.return_value = mock_response

        with pytest.raises(AgentError) as exc_info:
            agent_with_bedrock._call_bedrock_api("system", "user")

        assert "Invalid response structure" in str(exc_info.value)

    def test_bedrock_setup_creates_correct_client(self):
        """Verify Bedrock setup initializes boto3 client correctly."""
        with patch('boto3.client') as mock_boto_client:
            mock_client = MagicMock()
            mock_boto_client.return_value = mock_client

            config = {
                'type': 'bedrock',
                'bedrock_access_key_id': 'test-key',
                'bedrock_secret_access_key': 'test-secret',
            }

            agent = AgentClient(provider_config=config)

            # Verify boto3.client was called with correct parameters
            mock_boto_client.assert_called_once_with(
                'bedrock-runtime',
                region_name='eu-west-1',
                aws_access_key_id='test-key',
                aws_secret_access_key='test-secret',
            )

    def test_bedrock_setup_with_session_token(self):
        """Verify Bedrock setup includes session token when provided."""
        with patch('boto3.client') as mock_boto_client:
            mock_client = MagicMock()
            mock_boto_client.return_value = mock_client

            config = {
                'type': 'bedrock',
                'bedrock_access_key_id': 'test-key',
                'bedrock_secret_access_key': 'test-secret',
                'bedrock_session_token': 'test-token',
            }

            agent = AgentClient(provider_config=config)

            # Verify session token was included
            mock_boto_client.assert_called_once_with(
                'bedrock-runtime',
                region_name='eu-west-1',
                aws_access_key_id='test-key',
                aws_secret_access_key='test-secret',
                aws_session_token='test-token',
            )

    def test_analyze_evidence_separates_prompts_for_bedrock(self, agent_with_bedrock, bedrock_client_mock):
        """Verify analyze_evidence passes separated prompts to Bedrock."""
        # Mock the response
        nova_response = {
            "output": {
                "message": {
                    "content": [
                        {
                            "text": json.dumps({
                                "skill": "iam",
                                "findings": [],
                                "summary": {
                                    "total_findings": 0,
                                    "critical": 0,
                                    "high": 0,
                                    "medium": 0,
                                    "low": 0,
                                    "overall_risk_score": 0.0
                                },
                                "analyzed_at": "2026-01-23T00:00:00Z",
                                "evidence_count": 0,
                                "checklist_version": "2.0"
                            })
                        }
                    ]
                }
            }
        }

        mock_response = MagicMock()
        mock_response['body'].read.return_value = json.dumps(nova_response)
        bedrock_client_mock.invoke_model.return_value = mock_response

        # Call analyze_evidence
        evidence = {"users": []}
        checklist = {"items": []}

        findings = agent_with_bedrock.analyze_evidence("iam", evidence, checklist)

        # Verify bedrock API was called
        bedrock_client_mock.invoke_model.assert_called_once()

        # Verify request has correct structure
        call_kwargs = bedrock_client_mock.invoke_model.call_args[1]
        request_body = json.loads(call_kwargs['body'])

        # Verify system and user prompts are separated
        assert 'system' in request_body
        assert 'messages' in request_body
        assert request_body['system'][0]['text']  # Non-empty system prompt
        assert request_body['messages'][0]['content'][0]['text']  # Non-empty user prompt

        # Verify they are NOT combined
        assert "\n\n" not in request_body['system'][0]['text']  # System prompt should not include separator


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
