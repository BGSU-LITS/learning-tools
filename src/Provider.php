<?php
/**
 * Learning Tools Interoperability (LTI) Tool Provider
 * @author John Kloor <kloor@bgsu.edu>
 * @copyright 2015 Bowling Green State University Libraries
 * @license MIT
 * @package LearningTools
 */

namespace BGSULITS\LearningTools;

use \BGSULITS\LearningTools\Exceptions\ProviderConfigException;
use \BGSULITS\LearningTools\Exceptions\ProviderResultException;
use \BaglerIT\OAuthSimple\OAuthSimple;

/** A class to help create a LTI Tool Provider. */
class Provider
{
    /**
     * The description of the response.
     * @var string
     * @see Provider::sendResult() Sets this parameter.
     */
    public $resultDescription = '';

    /**
     * The score from the response action of "read".
     * @var float
     * @see Provider::sendResult() Sets this parameter.
     */
    public $resultScore = null;

    /**
     * An instance of the OAuthSimple class.
     * @var object
     * @see Provider::__construct() Sets this parameter.
     */
    private $oauth;

    /**
     * Construct the class.
     * @param string $key OAuth1 consumer key used for message signing.
     * @param string $secret OAuth1 consumer secret used for message signing.
     */
    public function __construct($key, $secret)
    {
        $this->oauth = new OAuthSimple($key, $secret);
    }

    /**
     * Verify the OAuth1 signature of a request.
     * @param string $url URL of the request.
     * @param string $action Action of the requet, i.e. "POST" or "GET".
     * @param array $parameters Parameters of the request typically from a
     *     superglobal, i.e. $_POST or $_GET.
     * @return bool True if the signature was verified. Otherwise false.
     * @throws ProviderConfigException Signature to verify could not be found.
     */
    public function verify($url, $action, $parameters)
    {
        // The oauth_signature must be among the parameters to verify.
        if (empty($parameters['oauth_signature'])) {
            throw new ProviderConfigException(
                'The signature to verify could not be found.'
            );
        }

        // Reset the OAuthSimple object, and set the request.
        $this->oauth->reset();
        $this->oauth->setURL($url);
        $this->oauth->setAction($action);
        $this->oauth->setParameters($parameters);

        // Sign the request, and compare with the specified signature.
        $result = $this->oauth->sign();
        $signature = $result['parameters']['oauth_signature'];
        return hash_equals($parameters['oauth_signature'], $signature);
    }

    /**
     * Verify the OAuth1 signature of the POST request.
     * @return bool True if the signature was verified. Otherwise false.
     * @throws ProviderConfigException Signature to verify could not be found.
     */
    public function verifyPost()
    {
        // Begin building the URL with the protocol.
        $url = 'http://';

        if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
            $url = 'https://';
        }

        // Add server name to the URL.
        $url .= $_SERVER['SERVER_NAME'];

        // Add the port to the URL if it isn't the standard HTTP/HTTPS port.
        // This is impercise to accommodate HTTP servers behind HTTPS proxies.
        if (!in_array($_SERVER['SERVER_PORT'], [80, 443])) {
            $url .= ':'. $_SERVER['SERVER_PORT'];
        }

        // Add the requested path to the URL.
        $url .= $_SERVER['REQUEST_URI'];

        // Verify the data in the POST superglobal for the URL created.
        return $this->verify($url, 'POST', $_POST);
    }

    /**
     * Makes an XML document to use as the body of a result request.
     * @param string $sourcedid The SourcedID to apply the request to.
     * @param string $action The action to apply:
     *     "read" to get the SourcedID's current score, the default.
     *     "replace" to set the SourcedID's score.
     *     "delete" to remove the SourcedID's score.
     * @param int|bool $score For the "replace" action, a float between 0 and
     *     1 inclusive that represents the percentage score for the SourcedID.
     *     Otherwise, the default of false.
     * @return string An XML document to send to an outcome service.
     * @throws ProviderConfigException An invalid result action was specified,
     *     or the "replace" action score was not specified as a number between
     *     0 and 1 inclusive.
     */
    public function makeResultBody(
        $sourcedid,
        $action = 'read',
        $score = false
    ) {
        // Verify the action.
        if (!in_array($action, ['read', 'replace', 'delete'])) {
            throw new ProviderConfigException(
                'The result action must be read, replace or delete.'
            );
        }

        // Create the root of the XML document.
        $root = new \SimpleXMLElement('<imsx_POXEnvelopeRequest/>');
        $root->addAttribute(
            'xmlns',
            'http://www.imsglobal.org/services/ltiv1p1/xsd/imsoms_v1p0'
        );

        // Setup the document header.
        $node = $root->addChild('imsx_POXHeader');
        $node = $node->addChild('imsx_POXRequestHeaderInfo');
        $node->addChild('imsx_version', 'V1.0');
        $node->addChild('imsx_messageIdentifier', uniqid());

        // Setup the document body, based upon the action.
        $node = $root->addChild('imsx_POXBody');
        $node = $node->addChild($action. 'ResultRequest');
        $part = $node->addChild('resultRecord');

        // Add the SourcedID to the doucment body.
        $node = $part->addChild('sourcedGUID');
        $node->addChild('sourcedId', $sourcedid);

        // For only the replace action, add the score to the document body.
        if ($action === 'replace') {
            // Verify that the score appears to be a number.
            if (!is_numeric($score)) {
                throw new ProviderConfigException(
                    'The result score must be a number.'
                );
            }

            // Convert the number to a float if neccessary.
            $score = (float) $score;

            // Make sure the score is between 0 and 1 inclusive.
            if ($score < 0 || $score > 1) {
                throw new ProviderConfigException(
                    'The result score must be between 0 and 1 inclusive.'
                );
            }

            // Add the score to the document body.
            $node = $part->addChild('result');
            $node = $node->addChild('resultScore');
            $node->addChild('language', 'en');
            $node->addChild('textString', $score);
        }

        // Convert the XML document to a DOM object, and format the result.
        $dom = dom_import_simplexml($root)->ownerDocument;
        $dom->encoding = 'UTF-8';
        $dom->formatOutput = true;

        // Return the XML document as a string.
        return $dom->saveXML();
    }

    /**
     * Makes an Authorization header to use in the header of a result request.
     * @param string $url The URL the request will be made against.
     * @param string $body The body that will be posted to the URL.
     * @return string The Authorization header for the URL and body.
     */
    public function makeResultAuth($url, $body)
    {
        // Create a hash of the body.
        $hash = base64_encode(sha1($body, true));

        // Reset the OAuthSimple object, and set the request.
        $this->oauth->reset();
        $this->oauth->setURL($url);

        // The action will always be POST.
        $this->oauth->setAction('POST');

        // Add the hash of the body as a parameter.
        $this->oauth->setParameters(['oauth_body_hash' => $hash]);

        // Sign the request, and return the Authorization header.
        $result = $this->oauth->sign();
        return($result['header']);
    }

    /**
     * Send a result request to an outcome service.
     * @param array $parameters An array of parameters that must contain an
     *     item keyed "lis_outcome_service_url" that provides the URL of the
     *     outcome service, and an item keyed "lis_result_sourcedid" that
     *     contains the SourcedID the result request is for. Typically the POST
     *     superglobal is specified.
     * @param string $action The action to apply:
     *     "read" to get the SourcedID's current score, the default.
     *     "replace" to set the SourcedID's score.
     *     "delete" to remove the SourcedID's score.
     * @param int|bool $score For the "replace" action, a float between 0 and
     *     1 inclusive that represents the percentage score for the SourcedID.
     *     Otherwise, the default of false.
     * @return bool True if the request was a success. Otherwise false.
     * @see Provider::$resultDescription Any description from the result.
     * @see Provider::$resultScore Any score from the result.
     * @throws ProviderConfigException An invalid result action was specified,
     *     or the "replace" action score was not specified as a number between
     *     0 and 1 inclusive, or the outcome service URL or SourcedID were not
     *     in the parameters.
     * @throws ProviderResultException The request failed, or the data
     *     retrieved was an invalid XML document.
     */
    public function sendResult(
        $parameters,
        $action = 'read',
        $score = false
    ) {
        // Check that the outcome service URL is available.
        if (empty($parameters['lis_outcome_service_url'])) {
            throw new ProviderConfigException(
                'The outcome service URL is unavailable.'
            );
        }

        $url = $parameters['lis_outcome_service_url'];

        // Check that the SourcedID is available.
        if (empty($parameters['lis_result_sourcedid'])) {
            throw new ProviderConfigException(
                'The result sourced ID is unavailable.'
            );
        }

        $sourcedid = $parameters['lis_result_sourcedid'];

        // Create the body and Authorization header for the request.
        $body = $this->makeResultBody($sourcedid, $action, $score);
        $auth = $this->makeResultAuth($url, $body);

        // Create a new stream context for the request that will post the body
        // as an XML document with the Authorization header.
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => [
                    'Authorization: '. $auth,
                    'Content-Type: application/xml'
                ],
                'content' => $body
            ]
        ]);

        // Perform the request against the outcome service URL in context.
        // Use the at-sign operator to surpress errors to be handled below.
        $data = @file_get_contents($url, false, $context);

        // If data was not retrieved from the request, an error occurred.
        if ($data === false) {
            // Get the error message, and throw it as ProviderResultException.
            $error = error_get_last();

            throw new ProviderResultException(
                'The result could not be sent to the consumer ('.
                $error['message']. ').'
            );
        }

        // Prevent errors in the XML retrieved from stopping program execution.
        libxml_use_internal_errors(true);

        // Load the data received into a SimpleXML object.
        $root = simplexml_load_string($data);

        // Throw an error if the data retrieved was not valid XML.
        if ($root === false) {
            throw new ProviderResultException(
                'The consumer provided an invalid XML document.'
            );
        }

        // Store the resultDescription if found in the XML document.
        $description = $root
            ->imsx_POXHeader
            ->imsx_POXResponseHeaderInfo
            ->imsx_statusInfo
            ->imsx_description;

        $this->resultDescription = '';

        if ($description) {
            $this->resultDescription = (string) $description;
        }

        // Store the resultScore if found in the XML document.
        $score = $root
            ->imsx_POXBody
            ->readResultResponse
            ->result
            ->resultScore
            ->textString;

        $this->resultScore = null;

        if ($score && (string) $score !== '') {
            $this->resultScore = (float) $score;
        }

        // Return whether the request was considered a success.
        return $info->imsx_codeMajor == 'success';
    }

    /**
     * Sends a read result request to an outcome service based on POST.
     * @return bool True if the request was a success. Otherwise false.
     * @see Provider::$resultDescription Any description from the result.
     * @see Provider::$resultScore Any score from the result.
     * @throws ProviderConfigException An invalid result action was specified,
     *     or the outcome service URL or SourcedID were not in the parameters.
     * @throws ProviderResultException The request failed, or the data
     *     retrieved was an invalid XML document.
     */
    public function sendResultRead()
    {
        return $this->sendResult($_POST, 'read');
    }

    /**
     * Sends a replace result request to an outcome service based on POST.
     * @param int|bool $score A float between 0 and 1 inclusive that represents
     *     the percentage score for the SourcedID.
     * @return bool True if the request was a success. Otherwise false.
     * @see Provider::$resultDescription Any description from the result.
     * @see Provider::$resultScore Any score from the result.
     * @throws ProviderConfigException An invalid result action was specified,
     *     or the "replace" action score was not specified as a number between
     *     0 and 1 inclusive, or the outcome service URL or SourcedID were not
     *     in the parameters.
     * @throws ProviderResultException The request failed, or the data
     *     retrieved was an invalid XML document.
     */
    public function sendResultReplace($score)
    {
        return $this->sendResult($_POST, 'replace', $score);
    }

    /**
     * Sends a delete result request to an outcome service based on POST.
     * @see Provider::$resultDescription Any description from the result.
     * @throws ProviderConfigException An invalid result action was specified,
     *     or the outcome service URL or SourcedID were not in the parameters.
     * @throws ProviderResultException The request failed, or the data
     *     retrieved was an invalid XML document.
     */
    public function sendResultDelete()
    {
        return $this->sendResult($_POST, 'delete');
    }
}
