package com.binitech.auth.domain;

/** Delivered only to the authenticated application mail adapter, never to a public caller. */
public record RecoveryDelivery(String username, String email, String token) {}
