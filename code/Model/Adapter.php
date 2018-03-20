<?php

/**
 * @author Daniel Deady <daniel@clockworkgeek.com>
 * @license MIT
 */
class Clockworkgeek_ApiBasicAuth_Model_Adapter extends Mage_Api2_Model_Auth_Adapter_Abstract
{

    /**
     * True if basic HTTP authentication is in use
     *
     * Do not issue a <code>WWW-Authenticate</code> challenge
     * because there may be other auths processed after this.
     *
     * @see Mage_Api2_Model_Auth_Adapter_Abstract::isApplicableToRequest()
     */
    public function isApplicableToRequest(Mage_Api2_Model_Request $request)
    {
        $headerValue = $request->getHeader('Authorization');

        return $headerValue && 'basic ' === strtolower(substr($headerValue, 0, 6));
    }

    /**
     * Try logging in as admin then customer
     * 
     * Throws an Unauthorized exception if neither group is acceptable.
     * Guests must omit authorization completely to avoid exception.
     *
     * @param Mage_Api2_Model_Request $request
     * @return stdClass
     * @see Mage_Api2_Model_Auth_Adapter_Abstract::getUserParams()
     * @throws Mage_Api2_Exception
     */
    public function getUserParams(Mage_Api2_Model_Request $request)
    {
        $headerValue = $request->getHeader('Authorization');
        preg_match('/^Basic ([a-z0-9+\/]+=*)$/i', $headerValue, $value);
        $slug = base64_decode(@$value[1]);
        if (substr_count($slug, ':') !== 1) {
            throw new Mage_Api2_Exception('Authorization is badly formed', Mage_Api2_Model_Server::HTTP_BAD_REQUEST);
        }

        list($username, $password) = explode(':', $slug);

        /** @var $admin Mage_Admin_Model_User */
        $admin = Mage::getModel('admin/user');
        // do not use Mage_Admin_Model_User::authenticate() because it does work for logging into backend
        $admin->loadByUsername($username);
        if ($admin->getId() && $admin->validateCurrentPassword($password) === true && $admin->getIsActive() && $admin->hasAssigned2Role($admin)) {
            return (object) array(
                'type' => Mage_Api2_Model_Auth_User_Admin::USER_TYPE,
                'id' => $admin->getId()
            );
        }

        $store = $request->getParam('store') ? Mage::app()->getStore($request->getParam('store')) : Mage::app()->getDefaultStoreView();
        /** @var $customer Mage_Customer_Model_Customer */
        $customer = $this->_getCustomerByEmail($username, $store->getWebsiteId());
        if ((!$customer->getConfirmation() || !$customer->isConfirmationRequired()) && $customer->validatePassword($password)) {
            return (object) array(
                'type' => Mage_Api2_Model_Auth_User_Customer::USER_TYPE,
                'id' => $customer->getId()
            );
        }

        throw new Mage_Api2_Exception('Unauthorized', Mage_Api2_Model_Server::HTTP_UNAUTHORIZED);
    }

    /**
     * Similar to <code>loadByEmail()</code> but only loads essential attributes
     *
     * @param string $email
     * @param int $websiteId
     * @return Mage_Customer_Model_Customer
     * @see Mage_Customer_Model_Customer::loadByEmail
     */
    protected function _getCustomerByEmail($email, $websiteId)
    {
        /** @var $customer Mage_Customer_Model_Customer */
        $customer = Mage::getModel('customer/customer');
        /** @var $resource Mage_Customer_Model_Resource_Customer */
        $resource = $customer->getResource();
        $adapter = $resource->getReadConnection();
        $bind    = array('customer_email' => $email);
        $select  = $adapter->select()
            ->from($resource->getEntityTable(), array($resource->getEntityIdField()))
            ->where('email = :customer_email');
        
        if ($customer->getSharingConfig()->isWebsiteScope()) {
            $bind['website_id'] = $websiteId;
            $select->where('website_id = :website_id');
        }
        
        $customerId = $adapter->fetchOne($select, $bind);
        $customer->load($customerId, array('confirmation', 'entity_id', 'password_hash'));
        return $customer;
    }
}
